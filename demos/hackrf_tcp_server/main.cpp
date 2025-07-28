#include <cmath>
#include <cstring>
#include <fstream>
#include <iostream>
#include <libhackrf/hackrf.h>
#include <netinet/in.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include "../../tinyflex.h"
#include "config.hpp"
#include "fsk.hpp"
#include "hackrf_util.hpp"
#include "flex_util.hpp"
#include "tcp_util.hpp"
#include "iq_util.hpp"
#include "hackrf_tx_util.hpp"

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

    int PORT        = config.PORT;
    int SAMPLE_RATE = config.SAMPLE_RATE;
    int BITRATE     = config.BITRATE;
    int AMPLITUDE   = config.AMPLITUDE;
    int FREQ_DEV    = config.FREQ_DEV;
    int TX_GAIN     = config.TX_GAIN;


    // TCP server setup
    struct sockaddr_in address;
    int server_fd = setup_tcp_server(PORT, address);
    if (server_fd < 0) {
        return 1;
    }

    int client_fd;
    int addrLen = sizeof(address);
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

        int capcode   = std::stoi(capcode_str);
        int frequency = std::stoi(freq_str);
        printf("Received: CAPCODE=%d, MESSAGE='%s', FREQUENCY=%d\n", capcode, message.c_str(), frequency);

        // Encode message using TinyFlex
        uint8_t flex_buffer[1024];
        int error = 0;
        size_t flex_len = 0;
        if (!encode_flex_message(message, capcode, flex_buffer, sizeof(flex_buffer), flex_len, error)) {
            printf("tf_encode_flex_message failed! Error code: %d\n", error);
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

        int result = 0;

        // Convert flex_buffer to binary vector
        std::vector<int> binary_data;
        for (size_t i = 0; i < flex_len; ++i) {
            for (int b = 7; b >= 0; --b) {
                binary_data.push_back((flex_buffer[i] >> b) & 0x01);
            }
        }

        double samples_per_bit    = (double)SAMPLE_RATE / BITRATE;
        int    samples_per_symbol = (int)samples_per_bit;
        double freq_0             = -FREQ_DEV; // Centered at 0, deviation -/+ FREQ_DEV
        double freq_1             = +FREQ_DEV;
            
        // Generate FSK I/Q signal using generate_fsk_signal
        std::vector<double> iq_signal = generate_fsk_signal(
            binary_data,
            freq_0,
            freq_1,
            SAMPLE_RATE,
            samples_per_symbol
        );

        // Convert to int8_t samples with amplitude scaling and clipping
        std::vector<int8_t> iq_samples;
        iq_samples.reserve(iq_signal.size());
        for (size_t i = 0; i < iq_signal.size(); ++i) {
            int val = static_cast<int>(std::round(AMPLITUDE * iq_signal[i]));
            if (val > 127) {
                val = 127;
            } else if (val < -127) {
                val = -127;
            }

            iq_samples.push_back(static_cast<int8_t>(val));
        }

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

        close_hackrf(device);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}