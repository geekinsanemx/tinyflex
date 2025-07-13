/*
 * tinyflex_serial: Modified tinyflex to send FLEX packets via serial.
 * Written by Davidson Francis (aka Theldus) and Rodrigo Laneth - 2025.
 *
 * This is free and unencumbered software released into the public domain.
 */

#define _DEFAULT_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>

#include "tinyflex.h"

/* Default serial parameters */
#define DEFAULT_DEVICE    "/dev/ttyACM0"
#define DEFAULT_BAUDRATE  115200
#define DEFAULT_FREQUENCY 929.3975
#define DEFAULT_POWER     2

static int loop_enabled = 0;
static const char *msg_errors[] = {
	"Invalid provided error pointer",
	"Invalid message buffer",
	"Invalid provided capcode",
	"Invalid provided flex buffer"
};

/* Serial configuration */
struct serial_config {
	char *device;
	uint32_t power;
	double frequency;
	uint32_t baudrate;
};

/* Global for TTY restoration */
static struct termios orig_tty;
static int tty_saved = 0;
static int serial_fd = -1;

/*
 * @brief Safe string-to-uint32_t routine.
 * Handles overflow, invalid characters, and rejects negative input.
 *
 * @param out Pointer to uint32_t.
 * @param s String to be converted.
 *
 * @return Returns 0 on success, -1 on error.
 */
static int str2uint32(uint32_t *out, const char *s)
{
	char *end;
	unsigned long ul;
	const char *p = s;

	/* Check for empty string or leading whitespace only */
	if (p[0] == '\0' || isspace(p[0]))
		return -1;

	/* Reject negative numbers */
	if (*p == '-')
		return -1;

	errno = 0;
	ul = strtoul(p, &end, 10);

	/* Check if:
	 * - No digits were found
	 * - Overflow
	 * - Extra chars at the end
	 * - If fits into uint32_t
	 */
	if (end == p || errno == ERANGE || *end != '\0' || ul > UINT32_MAX)
		return -1;

	*out = (uint32_t)ul;
	return 0;
}

/**
 * @brief Configures the serial port with the specified baudrate.
 *
 * @param fd File descriptor of the serial port.
 * @param baudrate Desired baudrate.
 * @return Returns 0 on success, -1 on error.
 */
static int configure_serial(int fd, int baudrate)
{
	struct termios tty;
	speed_t speed;

	if (tcgetattr(fd, &orig_tty) != 0) {
		perror("tcgetattr");
		return -1;
	}
	tty_saved = 1;
	serial_fd = fd;
	tty       = orig_tty;

	/* Convert baudrate to speed_t */
	switch (baudrate) {
	case 9600:   speed = B9600;   break;
	case 19200:  speed = B19200;  break;
	case 38400:  speed = B38400;  break;
	case 57600:  speed = B57600;  break;
	case 115200: speed = B115200; break;
	case 230400: speed = B230400; break;
	default:
		fprintf(stderr, "Unsupported baudrate: %d\n", baudrate);
		return -1;
	}

	cfsetospeed(&tty, speed);
	cfsetispeed(&tty, speed);
	cfmakeraw(&tty);

	/* TTY settings. */
	tty.c_cc[VMIN]  = 1;
	tty.c_cc[VTIME] = 10;
	tty.c_cflag &= ~CSTOPB;
	tty.c_cflag &= ~CRTSCTS; /* no HW flow control? */
	tty.c_cflag |= CLOCAL | CREAD;

    tty.c_cflag &= ~PARENB;  /* No parity. */
    tty.c_cflag &= ~CSIZE;   /* Clear size bits. */
    tty.c_cflag |= CS8;      /* 8 data bits. */
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);  /* No software flow control. */

	if (tcsetattr(fd, TCSANOW, &tty) != 0) {
		perror("tcsetattr");
		return -1;
	}

	return 0;
}

/**
 * @brief Restores original TTY settings if they were saved.
 */
static void restore_tty(void)
{
	if (tty_saved && serial_fd >= 0) {
		tcsetattr(serial_fd, TCSANOW, &orig_tty);
		tty_saved = 0;
	}
}

/**
 * @brief Sends a command and checks for response via serial.
 *
 * @param fd Serial file descriptor.
 * @param command Command to send.
 * @param error_msg Error message to display on failure.
 * @return Returns 0 on success, -1 on error.
 */
static int send_command_and_check(int fd, const char *command,
	const char *error_msg)
{
	char response[256];
	ssize_t bytes_written;
	ssize_t bytes_read;
	size_t  total_read;

	total_read = 0;

	printf("Sending command: (%s)\n", command);

	/* Send command */
	bytes_written = write(fd, command, strlen(command));
	if (bytes_written < 0) {
		perror("write");
		return -1;
	}
	bytes_written = write(fd, "\n", 1);
	if (bytes_written < 0) {
		perror("write");
		return -1;
	}
	tcdrain(fd);

	printf("Reading response...\n");

	/* Read response until newline or timeout */
	tcflush(fd, TCIFLUSH);
	while (total_read < sizeof(response) - 1) {
		bytes_read = read(fd, response + total_read, 1);
		if (bytes_read < 0) {
			perror("read");
			return -1;
		}
		if (bytes_read == 0) {
			fprintf(stderr, "Timeout reading response\n");
			return -1;
		}
		if (response[total_read] == '\n') {
			response[total_read] = '\0';
			break;
		}
		total_read++;
	}

	/* Check response format */
	if (strncmp(response, "__:0:", 5) != 0) {
		if (strncmp(response, "__:1:", 5) == 0) {
			fprintf(stderr, "Error: %s - Got response: %s\n",
				error_msg, response);
		} else {
			fprintf(stderr, "Unexpected response format: %s\n",
				response);
		}
		return -1;
	}

	return 0;
}

/**
 * @brief Sends binary data via serial and waits for response.
 *
 * @param fd Serial file descriptor.
 * @param data Binary data to send.
 * @param size Size of the data.
 * @return Returns 0 on success, -1 on error.
 */
static int send_binary_data(int fd, const uint8_t *data, size_t size)
{
	ssize_t bytes_written;
	size_t  total_written;
	char response[256];
	ssize_t bytes_read;
	size_t total_read;

	total_written = 0;
	total_read    = 0;

	printf("Sending binary data (%zu)...\n", size);

	/* Send all binary data */
	while (total_written < size) {
		bytes_written = write(fd, data + total_written, size - total_written);
		if (bytes_written < 0) {
			perror("write");
			return -1;
		}
		total_written += bytes_written;
	}
	tcdrain(fd);

	printf("Reading response for binary data...\n");

	/* Read response */
	tcflush(fd, TCIFLUSH);
	while (total_read < sizeof(response) - 1) {
		bytes_read = read(fd, response + total_read, 1);
		if (bytes_read < 0) {
			perror("read");
			return -1;
		}
		if (bytes_read == 0) {
			fprintf(stderr, "Timeout reading response\n");
			return -1;
		}
		if (response[total_read] == '\n') {
			response[total_read] = '\0';
			break;
		}
		total_read++;
	}

	printf("Response for binary data:\n");
	puts(response);
	puts("");

	/* Check response */
	if (strncmp(response, "__:0:", 5) != 0) {
		if (strncmp(response, "__:1:", 5) == 0)
			fprintf(stderr, "Error sending binary data: %s\n", response);
		else
			fprintf(stderr, "Unexpected response format: %s\n", response);
		return -1;
	}

	return 0;
}

/**
 * @brief Sends a flex message via serial.
 *
 * @param fd Serial file descriptor.
 * @param config Serial configuration.
 * @param data Binary flex data.
 * @param size Size of the data.
 * @return Returns 0 on success, -1 on error.
 */
static int send_flex_via_serial(int fd, struct serial_config *config,
	const uint8_t *data, size_t size)
{
	char cmd_buffer[64];

	/* Set frequency */
	snprintf(cmd_buffer, sizeof(cmd_buffer), "f %.4f", config->frequency);
	if (send_command_and_check(fd, cmd_buffer, "Failed to set frequency") < 0)
		return -1;

	/* Set TX power */
	snprintf(cmd_buffer, sizeof(cmd_buffer), "p %d", config->power);
	if (send_command_and_check(fd, cmd_buffer, "Failed to set TX power") < 0)
		return -1;

	/* Send message length */
	snprintf(cmd_buffer, sizeof(cmd_buffer), "m %zu", size);
	if (send_command_and_check(fd, cmd_buffer,
		"Failed to set message length") < 0)
		return -1;

	/* Send binary data */
	if (send_binary_data(fd, data, size) < 0)
		return -1;

	return 0;
}

/**
 * @brief Prints the program usage information to stderr and exits.
 *
 * @param prgname The name of the executable program (argv[0]).
 */
static void usage(const char *prgname)
{
	fprintf(stderr,
		"%s [options] <capcode> <message>\n"
		"or:\n"
		"%s [options] [-l] (from stdin)\n\n"
		
		"Options:\n"
		"   -d <device>    Serial device (default: %s)\n"
		"   -b <baudrate>  Baudrate (default: %d)\n"
		"   -f <frequency> Frequency in MHz (default: %f)\n"
		"   -p <power>     TX power (default: %d, 2-17)\n\n"

		"Stdin mode:\n"
		"   -l Loop mode (optional): stays open receiving new lines\n"
		"                            until EOF\n"
		"   Example:\n"
		"     printf '1234567:MY MESSAGE'               | %s\n"
		"     printf '1234567:MY MSG1\\n1122334:MY MSG2' | %s -l\n\n"

		"Normal mode:\n"
		"   %s 1234567 'MY MESSAGE'\n"
		"   %s -d /dev/ttyUSB0 -f 915.5 1234567 'MY MESSAGE'",
		prgname, prgname, DEFAULT_DEVICE, DEFAULT_BAUDRATE,
		DEFAULT_FREQUENCY, DEFAULT_POWER, prgname, prgname,
		prgname, prgname);
	exit(1);
}

/**
 * @brief Parses command line options and arguments.
 *
 * @param capcode  Capcode destination pointer (for normal mode).
 * @param msg      Message buffer (for normal mode).
 * @param argc     duh
 * @param argv     duh
 * @param config   Serial configuration struct to fill.
 * @param is_stdin Set to 1 if stdin mode, 0 for normal mode.
 */
static void read_params(uint32_t *capcode, char *msg, int argc, char **argv,
	struct serial_config *config, int *is_stdin)
{
	int non_opt_start;
	size_t msg_size;
	int opt;

	/* Initialize defaults */
	config->device    = DEFAULT_DEVICE;
	config->baudrate  = DEFAULT_BAUDRATE;
	config->frequency = DEFAULT_FREQUENCY;
	config->power     = DEFAULT_POWER;

	/* Parse options */
	while ((opt = getopt(argc, argv, "d:b:f:p:l")) != -1) {
		switch (opt) {
		case 'd':
			config->device = optarg;
			break;
		case 'b':
			if (str2uint32(&config->baudrate, optarg) < 0) {
				fprintf(stderr, "Invalid baudrate: %s\n", optarg);
				usage(argv[0]);
			}
			break;
		case 'f':
			config->frequency = atof(optarg);
			if (config->frequency <= 0) {
				fprintf(stderr, "Invalid frequency: %s\n", optarg);
				usage(argv[0]);
			}
			break;
		case 'p':
			if (str2uint32(&config->power, optarg) < 0 || 
				config->power < 2 || config->power > 17)
			{
				fprintf(stderr, "Invalid power: %s\n", optarg);
				usage(argv[0]);
			}
			break;
		case 'l':
			loop_enabled = 1;
			break;
		default:
			usage(argv[0]);
		}
	}

	non_opt_start = optind;

	/* Check remaining arguments */
	if (argc - non_opt_start == 2) {
		/* Normal mode: capcode and message */
		if (str2uint32(capcode, argv[non_opt_start]) < 0) {
			fprintf(stderr, "Invalid capcode: %s\n",
				argv[non_opt_start]);
			usage(argv[0]);
		}

		if ((msg_size = strlen(argv[non_opt_start + 1])) >= MAX_CHARS_ALPHA) {
			fprintf(stderr, "Message too long (max %d characters).\n",
				MAX_CHARS_ALPHA - 1);
			usage(argv[0]);
		}
		memcpy(msg, argv[non_opt_start + 1], msg_size + 1);
		*is_stdin = 0;
	}
	else if (argc - non_opt_start == 0) /* Stdin mode */
		*is_stdin = 1;
	else
		usage(argv[0]);
}

/**
 * @brief Reads a line from stdin, parses capcode and message.
 *
 * @param capcode_ptr Capcode destination pointer.
 * @param message_buf Destination parsed message buffer.
 * @param line_ptr    Line read pointer.
 * @param len_ptr     Line read length.
 * @return Returns 0 if success, 1 if EOF and 2 if parsing error.
 */
static int read_stdin_message(uint32_t *capcode_ptr, char *message_buf,
	char **line_ptr, size_t *len_ptr)
{
	char *current_message;
	ssize_t read_len;
	char *colon_pos;
	size_t msg_len;

	read_len = getline(line_ptr, len_ptr, stdin);
	if (read_len == -1)
		return 1; /* EOF or error */

	if (read_len > 0 && (*line_ptr)[read_len - 1] == '\n') {
		(*line_ptr)[read_len - 1] = '\0';
		read_len--;
	}

	colon_pos = strchr(*line_ptr, ':');
	if (colon_pos == NULL) {
		fprintf(stderr,
			"Invalid input: '%s', expected 'capcode:message'\n",
			*line_ptr);
		return 2;
	}
	*colon_pos = '\0';

	if (str2uint32(capcode_ptr, *line_ptr) < 0)  {
		fprintf(stderr, "Invalid capcode in input: '%s'\n", *line_ptr);
		return 2;
	}

	current_message = colon_pos + 1;
	msg_len         = read_len - (current_message - *line_ptr);

	if (msg_len >= MAX_CHARS_ALPHA) {
		fprintf(stderr,
			"Message too long in input: '%s' (max %d chars).\n",
			current_message, MAX_CHARS_ALPHA - 1);
		return 2;
	}
	memcpy(message_buf, current_message, msg_len + 1);
	return 0;
}

/**
 * @brief Signal handler to restore TTY on interrupt.
 *
 * @param sig Signal number.
 */
static void signal_handler(int sig)
{
	(void)sig; /* Unused */
	restore_tty();
	exit(1);
}

/* Main =). */
int main(int argc, char **argv)
{
	uint8_t vec[FLEX_BUFFER_SIZE] = {0};
	char message[MAX_CHARS_ALPHA] = {0};
	struct serial_config config;
	uint32_t capcode;
	size_t read_size;
	int is_stdin;
	char *line;
	int status;
	size_t len;
	int err;
	int ret;
	int fd;

	line = NULL;
	len  = 0;
	ret  = 1;
	fd   = -1;

	/* Restore TTY at the end. */
	atexit(restore_tty);
	signal(SIGINT,  signal_handler);
	signal(SIGTERM, signal_handler);

	read_params(&capcode, message, argc, argv, &config, &is_stdin);

	/* Open serial device */
	fd = open(config.device, O_RDWR | O_NOCTTY | O_SYNC);
	if (fd < 0) {
		fprintf(stderr, "Unable to open serial device '%s': %s\n",
			config.device, strerror(errno));
		goto error;
	}

	/* Configure serial port */
	if (configure_serial(fd, config.baudrate) < 0) {
		fprintf(stderr, "Failed to configure serial port\n");
		goto error;
	}

	/* Normal mode */
	if (!is_stdin) {
		read_size = tf_encode_flex_message(message, capcode, vec, sizeof vec, &err);
		if (err >= 0) {
			if (send_flex_via_serial(fd, &config, vec, read_size) < 0)
				goto error;
			printf("Successfully sent flex message\n");
		}
		else {
			fprintf(stderr, "Error encoding message: %s\n",
				msg_errors[-err]);
			goto error;
		}
		goto exit;
	}

	/* Stdin mode */
	do {
		status = read_stdin_message(&capcode, message, &line, &len);
		if (status == 1) /* EOF or read error */
			break;

		if (status == 2) { /* Parsing error */
			if (!loop_enabled)
				goto error;
			continue;
		}

		read_size = tf_encode_flex_message(message, capcode, vec, sizeof vec, &err);
		if (err >= 0) {
			if (send_flex_via_serial(fd, &config, vec, read_size) < 0) {
				if (!loop_enabled)
					goto error;
				/* In loop mode, continue on error */
				fprintf(stderr, "Failed to send message, continuing...\n");
			} else {
				printf("Sent %zu bytes for capcode %u\n",
					read_size, capcode);
			}
		}
		else {
			fprintf(stderr, "Error encoding message: %s\n", msg_errors[-err]);
			if (!loop_enabled)
				goto error;
		}
	} while (loop_enabled); /* Continue loop if enabled */

exit:
	ret = 0;
error:
	if (fd >= 0)
		close(fd);
	free(line);
	return ret;
}
