#include <cstring>
#include <iostream>
#include <libhackrf/hackrf.h>
#include <netinet/in.h>
#include <string>
#include <unistd.h>
#include "../../tinyflex.h"
#include "include/config.hpp"
#include "include/fsk.hpp"
#include "include/hackrf_util.hpp"
#include "include/flex_util.hpp"
#include "include/tcp_util.hpp"
#include "include/iq_util.hpp"

#ifndef M_TAU
// Why calculate 2 * PI when we can just use a constant?
#define M_TAU 6.28318530717958647692
#endif

int main(int argc, char* argv[]) {
    // Parse CLI arguments for --debug
    bool debug_mode = false;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--debug") {
            debug_mode = true;
        }
    }

    Config config;
    if (!load_config("config.txt", config)) {
        std::cerr << "Failed to open or parse config.txt!" << std::endl;
        return 1;
    }

    int PORT          = config.PORT;
    int SAMPLE_RATE   = config.SAMPLE_RATE;
    int BITRATE       = config.BITRATE;
    int AMPLITUDE     = config.AMPLITUDE;
    int FREQ_DEV      = config.FREQ_DEV;
    int TX_GAIN       = config.TX_GAIN;

    // TCP server setup
    struct sockaddr_in address;
    int server_fd     = setup_tcp_server(PORT, address);
    if (server_fd < 0) {
        return 1;
    }

    int client_fd;
    int addrLen       = sizeof(address);
    char buffer[2048] = {0};

    // Constant loop, waiting for a connection.
    printf("Waiting for client on port %d...\n", PORT);
    while (true) {
        // Accept a new connection
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrLen)) < 0) {
            perror("accept");
            break;
        }
        printf("Client connected!\n");

        // Read input from client
        int valRead = read(client_fd, buffer, sizeof(buffer) - 1);
        if (valRead <= 0) {
            perror("read");
            close(client_fd);
            continue;
        }

        buffer[valRead] = '\0';

        // Parse input: {CAPCODE}|{MESSAGE}|{FREQUENCY IN HZ}
        std::string input(buffer);
        size_t pos1 = input.find('|');
        size_t pos2 = input.rfind('|');
        if (pos1 == std::string::npos || pos2 == std::string::npos || pos1 == pos2) {
            printf("Invalid input format.\n");
            close(client_fd);
            continue;
        }

        std::string capcode_str = input.substr(0, pos1);
        std::string message     = input.substr(pos1 + 1, pos2 - pos1 - 1);
        std::string freq_str    = input.substr(pos2 + 1);

        uint64_t capcode;
        long frequency;

        try {
            capcode = std::stoull(capcode_str);
            int is_long;
            if (!is_capcode_valid(capcode, &is_long)) {
                throw std::invalid_argument("Invalid capcode: " + capcode_str);
            }
        } catch (const std::invalid_argument& e) {
            std::string error_msg = "Invalid capcode: " + capcode_str;
            printf("%s\n", error_msg.c_str());

            // Send message back to client
            send(client_fd, error_msg.c_str(), error_msg.size(), 0);
            // Close the client connection
            close(client_fd);
            continue;
        } catch (const std::out_of_range& e) {
            std::string error_msg = "Capcode out of range: " + capcode_str;
            printf("%s\n", error_msg.c_str());

            // Send message back to client
            send(client_fd, error_msg.c_str(), error_msg.size(), 0);
            // Close the client connection
            close(client_fd);
            continue;
        }

        try {
            frequency = std::stoul(freq_str);
            if (frequency < 1000000 || frequency > 6000000000) {
                throw std::out_of_range("Frequency out of valid range: " + freq_str);
            }
        } catch (const std::invalid_argument& e) {
            std::string error_msg = "Invalid frequency: " + freq_str;
            printf("%s\n", error_msg.c_str());
            // Send message back to client
            send(client_fd, error_msg.c_str(), error_msg.size(), 0);
            close(client_fd);
            continue;
        } catch (const std::out_of_range& e) {
            std::string error_msg = "Frequency out of valid range: " + freq_str;
            printf("%s\n", error_msg.c_str());

            // Send message back to client
            send(client_fd, error_msg.c_str(), error_msg.size(), 0);
            close(client_fd);
            continue;
        }

        printf("Received: CAPCODE=%llu, MESSAGE='%s', FREQUENCY=%ld\n",
               (unsigned long long)capcode, message.c_str(), frequency);

        // Encode message using TinyFlex
        uint8_t flex_buffer[1024];
        int error = 0;
        size_t flex_len = 0;
        if (!encode_flex_message(message, capcode, flex_buffer, sizeof(flex_buffer), flex_len, error)) {
            std::string error_msg = "Error encoding message: " + std::to_string(error);
            printf("%s\n", error_msg.c_str());

            // Send message back to client
            send(client_fd, error_msg.c_str(), error_msg.size(), 0);
            // Close the client connection
            close(client_fd);
            continue;
        }

        // This should only show if --debug was in the argument for starting the server.
        if (debug_mode) {
            printf("Encoded FLEX (%zu bytes): ", flex_len);
            for (size_t i = 0; i < flex_len; ++i) {
                printf("%02X ", flex_buffer[i]);
            }

            printf("\n");
        }

        // --- HackRF transmitter setup ---
        hackrf_device* device = setup_hackrf((uint64_t)frequency, SAMPLE_RATE, TX_GAIN);
        if (!device) {
            close(client_fd);
            continue;
        }

        // Generate FSK IQ samples from FLEX buffer
        std::vector<int8_t> iq_samples = generate_fsk_iq_samples(
            flex_buffer,
            flex_len,
            SAMPLE_RATE,
            BITRATE,
            AMPLITUDE,
            FREQ_DEV
        );

        // --- Transmit IQ samples ---
        if (debug_mode) {
            printf("%zu IQ samples...\n", iq_samples.size() / 2);
            // --- Write IQ samples to file for analysis ---
            write_iq_file("flexserver_output.iq", iq_samples);
        }

        // Only transmit if not in debug mode.
        if (!debug_mode) {
            transmit_hackrf(device, iq_samples);
        } else {
            printf("Debug mode active, skipping HackRF transmission.\n");
        }

        // Send success message back to client
        std::string success_msg = "Message sent successfully!";
        send(client_fd, success_msg.c_str(), success_msg.size(), 0);
        close_hackrf(device);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
