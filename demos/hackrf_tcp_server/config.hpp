#pragma once
#include <string>
#include <fstream>
#include <iostream>

struct Config {
    int PORT = 0;
    int SAMPLE_RATE = 0;
    int BITRATE = 0;
    int AMPLITUDE = 0;
    int FREQ_DEV = 0;
    int TX_GAIN = 0;
};

inline bool load_config(const std::string& filename, Config& cfg) {
    std::ifstream file(filename);
    if (!file.is_open()) return false;
    std::string line;
    while (std::getline(file, line)) {
        auto comment = line.find('#');
        if (comment != std::string::npos) line = line.substr(0, comment);
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        val.erase(0, val.find_first_not_of(" \t"));
        val.erase(val.find_last_not_of(" \t") + 1);
        if (key == "PORT") cfg.PORT = std::stoi(val);
        else if (key == "SAMPLE_RATE") cfg.SAMPLE_RATE = std::stoi(val);
        else if (key == "BITRATE") cfg.BITRATE = std::stoi(val);
        else if (key == "AMPLITUDE") cfg.AMPLITUDE = std::stoi(val);
        else if (key == "FREQ_DEV") cfg.FREQ_DEV = std::stoi(val);
        else if (key == "TX_GAIN") cfg.TX_GAIN = std::stoi(val);
    }
    return true;
}
