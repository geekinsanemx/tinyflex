#pragma once
#include <string>
#include <map>
#include <sstream>
#include <fstream>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <algorithm>
#include <crypt.h>

struct HttpRequest {
    std::string method;
    std::string path;
    std::string version;
    std::map<std::string, std::string> headers;
    std::string body;
};

struct JsonMessage {
    uint64_t capcode;
    std::string message;
    uint64_t frequency;
    bool valid;
};

// Simple base64 decode without OpenSSL dependency
inline std::string base64_decode(const std::string& encoded) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string decoded;

    int val = 0;
    int valb = -8;
    for (unsigned char c : encoded) {
        if (c == '=') break;

        size_t pos = chars.find(c);
        if (pos == std::string::npos) continue;

        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return decoded;
}

inline std::string trim(const std::string& str) {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

inline HttpRequest parse_http_request(const std::string& request) {
    HttpRequest req;

    std::istringstream stream(request);
    std::string line;

    // Parse request line
    if (std::getline(stream, line)) {
        line = trim(line);
        std::istringstream request_line(line);
        request_line >> req.method >> req.path >> req.version;
    }

    // Parse headers
    while (std::getline(stream, line) && !line.empty() && line != "\r") {
        line = trim(line);
        if (line.empty()) break;

        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = trim(line.substr(0, colon));
            std::string value = trim(line.substr(colon + 1));
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);
            req.headers[key] = value;
        }
    }

    // Parse body
    std::string body_line;
    while (std::getline(stream, body_line)) {
        req.body += body_line;
    }

    return req;
}

inline JsonMessage parse_json_message(const std::string& json) {
    JsonMessage msg;
    msg.valid = false;
    msg.frequency = 0; // Will use default if not provided

    // Simple JSON parsing (for production use a proper JSON library)
    size_t capcode_pos = json.find("\"capcode\"");
    size_t message_pos = json.find("\"message\"");
    size_t freq_pos = json.find("\"frequency\"");

    if (capcode_pos == std::string::npos || message_pos == std::string::npos) {
        return msg;
    }

    // Extract capcode
    size_t capcode_colon = json.find(':', capcode_pos);
    if (capcode_colon != std::string::npos) {
        size_t capcode_start = json.find_first_not_of(" \t", capcode_colon + 1);
        size_t capcode_end = json.find_first_of(",}", capcode_start);
        if (capcode_start != std::string::npos && capcode_end != std::string::npos) {
            std::string capcode_str = json.substr(capcode_start, capcode_end - capcode_start);
            try {
                msg.capcode = std::stoull(capcode_str);
            } catch (...) {
                return msg;
            }
        }
    }

    // Extract message
    size_t msg_colon = json.find(':', message_pos);
    if (msg_colon != std::string::npos) {
        size_t msg_quote_start = json.find('"', msg_colon);
        if (msg_quote_start != std::string::npos) {
            size_t msg_quote_end = json.find('"', msg_quote_start + 1);
            if (msg_quote_end != std::string::npos) {
                msg.message = json.substr(msg_quote_start + 1, msg_quote_end - msg_quote_start - 1);
            }
        }
    }

    // Extract frequency (optional)
    if (freq_pos != std::string::npos) {
        size_t freq_colon = json.find(':', freq_pos);
        if (freq_colon != std::string::npos) {
            size_t freq_start = json.find_first_not_of(" \t", freq_colon + 1);
            size_t freq_end = json.find_first_of(",}", freq_start);
            if (freq_start != std::string::npos && freq_end != std::string::npos) {
                std::string freq_str = json.substr(freq_start, freq_end - freq_start);
                try {
                    msg.frequency = std::stoull(freq_str);
                } catch (...) {
                    msg.frequency = 0; // Will use default
                }
            }
        }
    }

    msg.valid = !msg.message.empty();
    return msg;
}

inline std::map<std::string, std::string> load_passwords(const std::string& filename) {
    std::map<std::string, std::string> passwords;
    std::ifstream file(filename);

    if (!file.is_open()) {
        return passwords;
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string username = line.substr(0, colon);
            std::string hash = line.substr(colon + 1);
            passwords[username] = hash;
        }
    }

    return passwords;
}

inline bool create_default_passwords(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        return false;
    }

    // Create default admin/passw0rd entry using SHA512 hash (widely supported)
    // This is equivalent to: echo 'passw0rd' | htpasswd -i -6 passwords admin
    char* hash = crypt("passw0rd", "$6$hackrfsalt$");
    if (hash && hash[0] != '*') {
        file << "admin:" << hash << std::endl;
        std::cout << "Created default passwords file with admin/passw0rd (SHA512)" << std::endl;
    } else {
        // Fallback to plain text for testing (NOT recommended for production)
        file << "admin:passw0rd" << std::endl;
        std::cout << "Created default passwords file with admin/passw0rd (PLAIN TEXT - NOT SECURE)" << std::endl;
        std::cout << "WARNING: Plain text passwords are not secure. Use 'htpasswd -B passwords admin' for production." << std::endl;
    }

    file.close();
    return true;
}

inline bool verify_password(const std::string& password, const std::string& hash) {
    // Support for various hash formats that work on this system
    if (hash.substr(0, 3) == "$1$" ||      // MD5
        hash.substr(0, 3) == "$6$" ||      // SHA512
        hash.substr(0, 3) == "$2y" ||      // bcrypt
        hash.substr(0, 3) == "$2a" ||      // bcrypt
        hash.substr(0, 3) == "$2b") {      // bcrypt

        char* result = crypt(password.c_str(), hash.c_str());
        if (result && result[0] != '*') {
            return (hash == std::string(result));
        }
        return false;
    }
    else if (hash.substr(0, 6) == "$apr1$") {
        // Apache MD5 - not supported on this system
        std::cerr << "WARNING: Apache MD5 hashes ($apr1$) are not supported on this system." << std::endl;
        std::cerr << "Please recreate the passwords file using: htpasswd -B passwords username" << std::endl;
        return false;
    }
    else {
        // Plain text comparison (for testing only)
        return (password == hash);
    }
}

inline bool authenticate_user(const std::string& auth_header, const std::map<std::string, std::string>& passwords) {
    if (auth_header.substr(0, 6) != "Basic ") {
        return false;
    }

    std::string encoded = auth_header.substr(6);
    std::string decoded = base64_decode(encoded);

    size_t colon = decoded.find(':');
    if (colon == std::string::npos) {
        return false;
    }

    std::string username = decoded.substr(0, colon);
    std::string password = decoded.substr(colon + 1);

    auto it = passwords.find(username);
    if (it == passwords.end()) {
        return false;
    }

    return verify_password(password, it->second);
}

inline void send_http_response(int client_fd, int status_code, const std::string& status_text,
                              const std::string& body, const std::string& content_type = "text/plain") {
    std::ostringstream response;
    response << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
    response << "Content-Type: " << content_type << "\r\n";
    response << "Content-Length: " << body.length() << "\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << body;

    std::string response_str = response.str();
    send(client_fd, response_str.c_str(), response_str.length(), 0);
}

inline void send_unauthorized_response(int client_fd) {
    std::ostringstream response;
    response << "HTTP/1.1 401 Unauthorized\r\n";
    response << "WWW-Authenticate: Basic realm=\"HackRF HTTP Server\"\r\n";
    response << "Content-Type: application/json\r\n";
    response << "Content-Length: 47\r\n";
    response << "Connection: close\r\n";
    response << "\r\n";
    response << "{\"error\":\"Authentication required\",\"code\":401}";

    std::string response_str = response.str();
    send(client_fd, response_str.c_str(), response_str.length(), 0);
}
