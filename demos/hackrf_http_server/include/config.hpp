#pragma once
#include <string>
#include <fstream>
#include <iostream>

struct Config {
    std::string BIND_ADDRESS        = "127.0.0.1";
    u_int16_t   SERIAL_LISTEN_PORT  = 16175;
    u_int16_t   HTTP_LISTEN_PORT    = 16180;
    u_int64_t   SAMPLE_RATE         = 2000000;
    u_int16_t   BITRATE             = 1600;
    int8_t      AMPLITUDE           = 127;
    u_int32_t   FREQ_DEV            = 2400;
    u_int8_t    TX_GAIN             = 0;
    u_int64_t   DEFAULT_FREQUENCY   = 931937500;
};

inline bool load_config(const std::string& filename, Config& cfg) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        // Remove comments
        auto comment = line.find('#');
        if (comment != std::string::npos) {
            line = line.substr(0, comment);
        }

        size_t eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        // Trim whitespace
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        val.erase(0, val.find_first_not_of(" \t"));
        val.erase(val.find_last_not_of(" \t") + 1);

        // Remove trailing commas from values
        if (!val.empty() && val.back() == ',') {
            val.pop_back();
        }

        if (key == "BIND_ADDRESS") {
            cfg.BIND_ADDRESS = val;
        }
        else if (key == "SERIAL_LISTEN_PORT") {
            try {
                cfg.SERIAL_LISTEN_PORT = std::stoul(val);
            } catch (...) {
                std::cerr << "Invalid SERIAL_LISTEN_PORT value: " << val << std::endl;
                return false;
            }
        }
        else if (key == "HTTP_LISTEN_PORT") {
            try {
                cfg.HTTP_LISTEN_PORT = std::stoul(val);
            } catch (...) {
                std::cerr << "Invalid HTTP_LISTEN_PORT value: " << val << std::endl;
                return false;
            }
        }
        else if (key == "SAMPLE_RATE") {
            try {
                cfg.SAMPLE_RATE = std::stoull(val);
            } catch (...) {
                std::cerr << "Invalid SAMPLE_RATE value: " << val << std::endl;
                return false;
            }
        }
        else if (key == "BITRATE") {
            try {
                cfg.BITRATE = std::stoul(val);
            } catch (...) {
                std::cerr << "Invalid BITRATE value: " << val << std::endl;
                return false;
            }
        }
        else if (key == "AMPLITUDE") {
            try {
                cfg.AMPLITUDE = static_cast<int8_t>(std::stoi(val));
            } catch (...) {
                std::cerr << "Invalid AMPLITUDE value: " << val << std::endl;
                return false;
            }
        }
        else if (key == "FREQ_DEV") {
            try {
                cfg.FREQ_DEV = std::stoul(val);
            } catch (...) {
                std::cerr << "Invalid FREQ_DEV value: " << val << std::endl;
                return false;
            }
        }
        else if (key == "TX_GAIN") {
            try {
                cfg.TX_GAIN = static_cast<uint8_t>(std::stoi(val));
            } catch (...) {
                std::cerr << "Invalid TX_GAIN value: " << val << std::endl;
                return false;
            }
        }
        else if (key == "DEFAULT_FREQUENCY") {
            try {
                cfg.DEFAULT_FREQUENCY = std::stoull(val);
            } catch (...) {
                std::cerr << "Invalid DEFAULT_FREQUENCY value: " << val << std::endl;
                return false;
            }
        }
        // Support legacy PORT config
        else if (key == "PORT") {
            try {
                cfg.SERIAL_LISTEN_PORT = std::stoul(val);
            } catch (...) {
                std::cerr << "Invalid PORT value: " << val << std::endl;
                return false;
            }
        }
        else {
            std::cerr << "Unknown configuration key: " << key << std::endl;
            return false;
        }
    }

    return true;
}
