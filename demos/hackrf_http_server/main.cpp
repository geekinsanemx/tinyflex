#include <cstring>
#include <iostream>
#include <libhackrf/hackrf.h>
#include <netinet/in.h>
#include <string>
#include <unistd.h>
#include <cstdlib>
#include <chrono>
#include <thread>
#include <sys/select.h>
#include <errno.h>
#include "../../tinyflex.h"
#include "include/config.hpp"
#include "include/fsk.hpp"
#include "include/hackrf_util.hpp"
#include "include/flex_util.hpp"
#include "include/tcp_util.hpp"
#include "include/http_util.hpp"
#include "include/iq_util.hpp"

#ifndef M_TAU
// Why calculate 2 * PI when we can just use a constant?
#define M_TAU 6.28318530717958647692
#endif

void print_help() {
    std::cout << "hackrf_http_server - FLEX paging HTTP/TCP server for HackRF\n\n";
    std::cout << "USAGE:\n";
    std::cout << "  hackrf_http_server [OPTIONS]\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  --help, -h     Show this help message and exit\n";
    std::cout << "  --debug, -d    Enable debug mode (prints raw bytes, creates IQ file, skips transmission)\n";
    std::cout << "  --verbose, -v  Enable verbose output (detailed transmission info)\n\n";
    std::cout << "CONFIGURATION:\n";
    std::cout << "  The server reads configuration from config.ini (preferred) or falls back to\n";
    std::cout << "  environment variables if the file doesn't exist.\n\n";
    std::cout << "  Configuration parameters:\n";
    std::cout << "    BIND_ADDRESS        - IP address to bind to (default: 127.0.0.1)\n";
    std::cout << "    SERIAL_LISTEN_PORT  - TCP port for serial protocol (default: 16175, 0 = disabled)\n";
    std::cout << "    HTTP_LISTEN_PORT    - HTTP port for JSON API (default: 16180, 0 = disabled)\n";
    std::cout << "    SAMPLE_RATE         - HackRF sample rate (default: 2000000)\n";
    std::cout << "    BITRATE             - FSK bitrate (default: 1600)\n";
    std::cout << "    AMPLITUDE           - Signal amplitude (default: 127)\n";
    std::cout << "    FREQ_DEV            - Frequency deviation (default: 2400)\n";
    std::cout << "    TX_GAIN             - HackRF TX gain in dB, 0-47 (default: 0)\n";
    std::cout << "    DEFAULT_FREQUENCY   - Default frequency in Hz (default: 931937500)\n\n";
    std::cout << "SERIAL PROTOCOL (TCP):\n";
    std::cout << "  Send messages via TCP in format: {CAPCODE}|{MESSAGE}|{FREQUENCY_HZ}\n";
    std::cout << "  Example: echo '001122334|Hello World|925516000' | nc localhost 16175\n\n";
    std::cout << "HTTP PROTOCOL (JSON):\n";
    std::cout << "  POST JSON to HTTP port with basic authentication:\n";
    std::cout << "  {\n";
    std::cout << "    \"capcode\": 1122334,\n";
    std::cout << "    \"message\": \"Hello World\",\n";
    std::cout << "    \"frequency\": 925516000  // optional, uses DEFAULT_FREQUENCY if omitted\n";
    std::cout << "  }\n\n";
    std::cout << "AUTHENTICATION:\n";
    std::cout << "  HTTP requests require basic authentication. Credentials are stored in ./passwords\n";
    std::cout << "  file in htpasswd format. If the file doesn't exist, it will be created with\n";
    std::cout << "  default credentials: admin/passw0rd\n\n";
    std::cout << "  To add/update users, use the htpasswd tool:\n";
    std::cout << "    htpasswd -m passwords username    # Add/update user with MD5 hash\n";
    std::cout << "    htpasswd -B passwords username    # Add/update user with bcrypt hash\n";
    std::cout << "    htpasswd -D passwords username    # Delete user\n\n";
    std::cout << "EMR (Emergency Message Resynchronization):\n";
    std::cout << "  If this is the first message or no messages have been sent for more than\n";
    std::cout << "  10 minutes, the server will automatically send an EMR message before\n";
    std::cout << "  transmitting the actual message to ensure proper synchronization.\n\n";
}

struct ConnectionState {
    std::chrono::steady_clock::time_point last_transmission;
    bool first_message;

    ConnectionState() : first_message(true) {}
};

bool should_send_emr(ConnectionState& state) {
    if (state.first_message) {
        return true;
    }

    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::minutes>(
        now - state.last_transmission);

    return duration.count() >= 10;
}

void send_emr_messages(hackrf_device* device, const Config& config, bool verbose_mode) {
    if (verbose_mode) {
        std::cout << "Sending EMR (Emergency Message Resynchronization) message...\n";
    }

    // EMR message is typically a short synchronization burst
    // Using a standard EMR pattern for FLEX
    uint8_t emr_buffer[] = {0xA5, 0x5A, 0xA5, 0x5A}; // Simple sync pattern

    std::vector<int8_t> emr_iq_samples = generate_fsk_iq_samples(
        emr_buffer,
        sizeof(emr_buffer),
        config.SAMPLE_RATE,
        config.BITRATE,
        config.AMPLITUDE,
        config.FREQ_DEV
    );

    if (verbose_mode) {
        std::cout << "Transmitting EMR message...\n";
    }

    transmit_hackrf(device, emr_iq_samples);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    if (verbose_mode) {
        std::cout << "EMR transmission complete.\n";
    }
}

bool process_message(uint64_t capcode, const std::string& message, uint64_t frequency,
                    ConnectionState& conn_state, const Config& config,
                    bool debug_mode, bool verbose_mode) {

    if (verbose_mode) {
        printf("Processing message - CAPCODE=%llu, MESSAGE='%s', FREQUENCY=%llu Hz\n",
               (unsigned long long)capcode, message.c_str(), (unsigned long long)frequency);
    }

    // Validate capcode
    int is_long;
    if (!is_capcode_valid(capcode, &is_long)) {
        std::cerr << "Invalid capcode: " << capcode << std::endl;
        return false;
    }

    // Validate frequency
    if (frequency < 1000000 || frequency > 6000000000) {
        std::cerr << "Frequency out of valid range: " << frequency << std::endl;
        return false;
    }

    // Encode message using TinyFlex
    uint8_t flex_buffer[1024];
    int error = 0;
    size_t flex_len = 0;
    if (!encode_flex_message(message, capcode, flex_buffer, sizeof(flex_buffer), flex_len, error)) {
        std::cerr << "Error encoding message: " << error << std::endl;
        return false;
    }

    if (debug_mode || verbose_mode) {
        printf("Encoded FLEX (%zu bytes): ", flex_len);
        for (size_t i = 0; i < flex_len; ++i) {
            printf("%02X ", flex_buffer[i]);
        }
        printf("\n");
    }

    // --- HackRF transmitter setup ---
    hackrf_device* device = setup_hackrf(frequency, config.SAMPLE_RATE, config.TX_GAIN);
    if (!device) {
        return false;
    }

    // Check if we need to send EMR messages
    bool need_emr = should_send_emr(conn_state);
    if (need_emr && !debug_mode) {
        send_emr_messages(device, config, verbose_mode);
    } else if (need_emr && debug_mode) {
        std::cout << "Debug mode: Would send EMR messages here\n";
    }

    // Generate FSK IQ samples from FLEX buffer
    std::vector<int8_t> iq_samples = generate_fsk_iq_samples(
        flex_buffer,
        flex_len,
        config.SAMPLE_RATE,
        config.BITRATE,
        config.AMPLITUDE,
        config.FREQ_DEV
    );

    if (debug_mode || verbose_mode) {
        printf("Generated %zu IQ samples for transmission\n", iq_samples.size() / 2);
    }

    // --- Write IQ samples to file for analysis (debug mode) ---
    if (debug_mode) {
        write_iq_file("flexserver_output.iq", iq_samples);
    }

    // --- Transmit IQ samples ---
    if (!debug_mode) {
        if (verbose_mode) {
            std::cout << "Starting transmission...\n";
        }
        transmit_hackrf(device, iq_samples);

        // Update connection state
        conn_state.last_transmission = std::chrono::steady_clock::now();
        conn_state.first_message = false;
    } else {
        printf("Debug mode active, skipping HackRF transmission.\n");
    }

    close_hackrf(device);
    return true;
}

void handle_serial_client(int client_fd, ConnectionState& conn_state, const Config& config,
                         bool debug_mode, bool verbose_mode) {
    char buffer[2048] = {0};

    // Read input from client
    int valRead = read(client_fd, buffer, sizeof(buffer) - 1);
    if (valRead <= 0) {
        perror("read");
        return;
    }

    buffer[valRead] = '\0';

    // Parse input: {CAPCODE}|{MESSAGE}|{FREQUENCY IN HZ}
    std::string input(buffer);
    size_t pos1 = input.find('|');
    size_t pos2 = input.rfind('|');
    if (pos1 == std::string::npos || pos2 == std::string::npos || pos1 == pos2) {
        std::string error_msg = "Invalid input format. Expected: CAPCODE|MESSAGE|FREQUENCY";
        send(client_fd, error_msg.c_str(), error_msg.size(), 0);
        return;
    }

    std::string capcode_str = input.substr(0, pos1);
    std::string message     = input.substr(pos1 + 1, pos2 - pos1 - 1);
    std::string freq_str    = input.substr(pos2 + 1);

    uint64_t capcode;
    uint64_t frequency;

    try {
        capcode = std::stoull(capcode_str);
        frequency = std::stoull(freq_str);
    } catch (const std::exception& e) {
        std::string error_msg = "Invalid capcode or frequency format";
        send(client_fd, error_msg.c_str(), error_msg.size(), 0);
        return;
    }

    if (process_message(capcode, message, frequency, conn_state, config, debug_mode, verbose_mode)) {
        std::string success_msg = "Message sent successfully!";
        send(client_fd, success_msg.c_str(), success_msg.size(), 0);
    } else {
        std::string error_msg = "Failed to process message";
        send(client_fd, error_msg.c_str(), error_msg.size(), 0);
    }
}

void handle_http_client(int client_fd, const std::map<std::string, std::string>& passwords,
                       ConnectionState& conn_state, const Config& config,
                       bool debug_mode, bool verbose_mode) {
    char buffer[4096] = {0};

    // Read HTTP request
    int valRead = read(client_fd, buffer, sizeof(buffer) - 1);
    if (valRead <= 0) {
        send_http_response(client_fd, 400, "Bad Request",
                          "{\"error\":\"Failed to read request\",\"code\":400}", "application/json");
        return;
    }

    buffer[valRead] = '\0';
    HttpRequest request = parse_http_request(std::string(buffer));

    // Check if it's a POST request
    if (request.method != "POST") {
        send_http_response(client_fd, 405, "Method Not Allowed",
                          "{\"error\":\"Only POST method is allowed\",\"code\":405}", "application/json");
        return;
    }

    // Check authentication
    auto auth_it = request.headers.find("authorization");
    if (auth_it == request.headers.end() || !authenticate_user(auth_it->second, passwords)) {
        send_unauthorized_response(client_fd);
        return;
    }

    // Parse JSON message
    JsonMessage json_msg = parse_json_message(request.body);
    if (!json_msg.valid) {
        send_http_response(client_fd, 400, "Bad Request",
                          "{\"error\":\"Invalid JSON format or missing required fields\",\"code\":400}",
                          "application/json");
        return;
    }

    // Use default frequency if not provided
    uint64_t frequency = json_msg.frequency > 0 ? json_msg.frequency : config.DEFAULT_FREQUENCY;

    if (process_message(json_msg.capcode, json_msg.message, frequency, conn_state, config, debug_mode, verbose_mode)) {
        send_http_response(client_fd, 200, "OK",
                          "{\"status\":\"success\",\"message\":\"Message sent successfully\"}",
                          "application/json");
    } else {
        send_http_response(client_fd, 500, "Internal Server Error",
                          "{\"error\":\"Failed to process message\",\"code\":500}",
                          "application/json");
    }
}

int main(int argc, char* argv[]) {
    // Parse CLI arguments
    bool debug_mode = false;
    bool verbose_mode = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        if (arg == "--debug" || arg == "-d") {
            debug_mode = true;
        } else if (arg == "--verbose" || arg == "-v") {
            verbose_mode = true;
        } else if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            std::cerr << "Use --help for usage information." << std::endl;
            return 1;
        }
    }

    Config config;
    bool config_loaded = false;

    // Try to load config.ini first
    if (load_config("config.ini", config)) {
        config_loaded = true;
        if (verbose_mode) {
            std::cout << "Configuration loaded from config.ini\n";
        }
    } else {
        // Fall back to environment variables
        if (verbose_mode) {
            std::cout << "config.ini not found, using environment variables\n";
        }

        const char* env_bind = getenv("BIND_ADDRESS");
        const char* env_serial_port = getenv("SERIAL_LISTEN_PORT");
        const char* env_http_port = getenv("HTTP_LISTEN_PORT");
        const char* env_port = getenv("PORT"); // Legacy support
        const char* env_sample_rate = getenv("SAMPLE_RATE");
        const char* env_bitrate = getenv("BITRATE");
        const char* env_amplitude = getenv("AMPLITUDE");
        const char* env_freq_dev = getenv("FREQ_DEV");
        const char* env_tx_gain = getenv("TX_GAIN");
        const char* env_default_freq = getenv("DEFAULT_FREQUENCY");

        // Set defaults
        config.BIND_ADDRESS = env_bind ? std::string(env_bind) : "127.0.0.1";
        config.SERIAL_LISTEN_PORT = env_serial_port ? std::stoul(env_serial_port) :
                                   (env_port ? std::stoul(env_port) : 16175);
        config.HTTP_LISTEN_PORT = env_http_port ? std::stoul(env_http_port) : 16180;
        config.SAMPLE_RATE = env_sample_rate ? std::stoull(env_sample_rate) : 2000000;
        config.BITRATE = env_bitrate ? std::stoul(env_bitrate) : 1600;
        config.AMPLITUDE = env_amplitude ? static_cast<int8_t>(std::stoi(env_amplitude)) : 127;
        config.FREQ_DEV = env_freq_dev ? std::stoul(env_freq_dev) : 2400;
        config.TX_GAIN = env_tx_gain ? static_cast<uint8_t>(std::stoi(env_tx_gain)) : 0;
        config.DEFAULT_FREQUENCY = env_default_freq ? std::stoull(env_default_freq) : 931937500;

        config_loaded = true;
    }

    if (!config_loaded) {
        std::cerr << "Failed to load configuration!" << std::endl;
        return 1;
    }

    if (verbose_mode) {
        std::cout << "Configuration:\n";
        std::cout << "  BIND_ADDRESS: " << config.BIND_ADDRESS << "\n";
        std::cout << "  SERIAL_LISTEN_PORT: " << config.SERIAL_LISTEN_PORT << "\n";
        std::cout << "  HTTP_LISTEN_PORT: " << config.HTTP_LISTEN_PORT << "\n";
        std::cout << "  SAMPLE_RATE: " << config.SAMPLE_RATE << "\n";
        std::cout << "  BITRATE: " << config.BITRATE << "\n";
        std::cout << "  AMPLITUDE: " << static_cast<int>(config.AMPLITUDE) << "\n";
        std::cout << "  FREQ_DEV: " << config.FREQ_DEV << "\n";
        std::cout << "  TX_GAIN: " << static_cast<int>(config.TX_GAIN) << "\n";
        std::cout << "  DEFAULT_FREQUENCY: " << config.DEFAULT_FREQUENCY << "\n";
    }

    // Check if both ports are disabled
    if (config.SERIAL_LISTEN_PORT == 0 && config.HTTP_LISTEN_PORT == 0) {
        std::cerr << "Error: Both SERIAL_LISTEN_PORT and HTTP_LISTEN_PORT are disabled (set to 0)!" << std::endl;
        std::cerr << "At least one port must be enabled." << std::endl;
        return 1;
    }

    // Setup servers
    int serial_server_fd = -1;
    int http_server_fd = -1;
    struct sockaddr_in serial_address, http_address;

    if (config.SERIAL_LISTEN_PORT > 0) {
        serial_server_fd = setup_tcp_server(config.SERIAL_LISTEN_PORT, serial_address, config.BIND_ADDRESS);
        if (serial_server_fd < 0) {
            std::cerr << "Failed to setup serial TCP server" << std::endl;
            return 1;
        }
        printf("Serial TCP server listening on %s:%d\n", config.BIND_ADDRESS.c_str(), config.SERIAL_LISTEN_PORT);
    } else {
        printf("Serial TCP server disabled (port = 0)\n");
    }

    if (config.HTTP_LISTEN_PORT > 0) {
        http_server_fd = setup_tcp_server(config.HTTP_LISTEN_PORT, http_address, config.BIND_ADDRESS);
        if (http_server_fd < 0) {
            if (serial_server_fd >= 0) close(serial_server_fd);
            std::cerr << "Failed to setup HTTP server" << std::endl;
            return 1;
        }
        printf("HTTP server listening on %s:%d\n", config.BIND_ADDRESS.c_str(), config.HTTP_LISTEN_PORT);
    } else {
        printf("HTTP server disabled (port = 0)\n");
    }

    // Load or create passwords file for HTTP authentication
    std::map<std::string, std::string> passwords;
    if (config.HTTP_LISTEN_PORT > 0) {
        passwords = load_passwords("./passwords");
        if (passwords.empty()) {
            std::cout << "Passwords file not found, creating default one..." << std::endl;
            if (create_default_passwords("./passwords")) {
                passwords = load_passwords("./passwords");
            } else {
                std::cerr << "Failed to create default passwords file!" << std::endl;
                if (serial_server_fd >= 0) close(serial_server_fd);
                if (http_server_fd >= 0) close(http_server_fd);
                return 1;
            }
        }
        if (verbose_mode) {
            std::cout << "Loaded " << passwords.size() << " user(s) from passwords file\n";
        }
    }

    ConnectionState conn_state;
    printf("Server ready, waiting for connections...\n");

    // Main server loop using select()
    while (true) {
        fd_set read_fds;
        FD_ZERO(&read_fds);

        int max_fd = 0;
        if (serial_server_fd >= 0) {
            FD_SET(serial_server_fd, &read_fds);
            max_fd = std::max(max_fd, serial_server_fd);
        }
        if (http_server_fd >= 0) {
            FD_SET(http_server_fd, &read_fds);
            max_fd = std::max(max_fd, http_server_fd);
        }

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if (activity < 0 && errno != EINTR) {
            perror("select error");
            break;
        }

        // Handle serial TCP connections
        if (serial_server_fd >= 0 && FD_ISSET(serial_server_fd, &read_fds)) {
            socklen_t serial_addrlen = sizeof(serial_address);
            int client_fd = accept(serial_server_fd, (struct sockaddr *)&serial_address, &serial_addrlen);
            if (client_fd >= 0) {
                if (verbose_mode) {
                    std::cout << "Serial TCP client connected from " << inet_ntoa(serial_address.sin_addr) << "\n";
                } else {
                    printf("Serial TCP client connected!\n");
                }

                handle_serial_client(client_fd, conn_state, config, debug_mode, verbose_mode);
                close(client_fd);

                if (verbose_mode) {
                    std::cout << "Serial TCP client connection closed.\n";
                }
            }
        }

        // Handle HTTP connections
        if (http_server_fd >= 0 && FD_ISSET(http_server_fd, &read_fds)) {
            socklen_t http_addrlen = sizeof(http_address);
            int client_fd = accept(http_server_fd, (struct sockaddr *)&http_address, &http_addrlen);
            if (client_fd >= 0) {
                if (verbose_mode) {
                    std::cout << "HTTP client connected from " << inet_ntoa(http_address.sin_addr) << "\n";
                } else {
                    printf("HTTP client connected!\n");
                }

                handle_http_client(client_fd, passwords, conn_state, config, debug_mode, verbose_mode);
                close(client_fd);

                if (verbose_mode) {
                    std::cout << "HTTP client connection closed.\n";
                }
            }
        }
    }

    // Cleanup
    if (serial_server_fd >= 0) close(serial_server_fd);
    if (http_server_fd >= 0) close(http_server_fd);
    return 0;
}
