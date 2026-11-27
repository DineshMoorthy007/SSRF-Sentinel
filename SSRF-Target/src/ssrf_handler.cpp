#include "ssrf_handler.h"

#include <iostream>
#include <sstream>
#include <string>
#include <set>
#include <vector>
#include <cctype>
#include <algorithm>

std::string SSRFHandler::urlDecode(const std::string& in) {
    std::string out;
    out.reserve(in.length());
    for (size_t i = 0; i < in.length(); ++i) {
        if (in[i] == '%' && i + 2 < in.length()) {
            std::string hex = in.substr(i + 1, 2);
            try {
                char c = static_cast<char>(std::stoi(hex, nullptr, 16));
                out += c;
                i += 2;
                continue;
            } catch (...) {}
        }
        if (in[i] == '+') {
            out += ' ';
        } else {
            out += in[i];
        }
    }
    return out;
}

// Parses alternative IPv4 representations (decimal, octal, hex, shorthand, IPv6)
// Returns true if the host is a recognized alternative notation for 127.0.0.1
bool SSRFHandler::parseIPv4Alternative(const std::string& host_str, std::string& out_ip, std::string& out_type) {
    if (host_str.empty()) return false;

    // 1. IPv6 loopback: [::1], ::1, [0:0:0:0:0:0:0:1]
    if (host_str == "::1" || host_str == "[::1]" || host_str == "0:0:0:0:0:0:0:1" || host_str == "[0:0:0:0:0:0:0:1]") {
        out_ip = "127.0.0.1";
        out_type = "ipv6_loopback";
        return true;
    }

    // 2. Dword / Decimal integer representation (e.g. 2130706433 -> 127.0.0.1)
    bool allDigits = true;
    for (char c : host_str) {
        if (!std::isdigit(static_cast<unsigned char>(c))) {
            allDigits = false;
            break;
        }
    }
    if (allDigits && !host_str.empty()) {
        try {
            unsigned long long val = std::stoull(host_str);
            if (val == 2130706433ULL) { // 127.0.0.1
                out_ip = "127.0.0.1";
                out_type = "decimal_dword";
                return true;
            }
        } catch (...) {}
    }

    // 3. Hex integer representation (e.g. 0x7f000001 -> 127.0.0.1)
    if (host_str.rfind("0x", 0) == 0 || host_str.rfind("0X", 0) == 0) {
        try {
            unsigned long val = std::stoul(host_str, nullptr, 16);
            if (val == 0x7F000001UL) {
                out_ip = "127.0.0.1";
                out_type = "hex_dword";
                return true;
            }
        } catch (...) {}
    }

    // 4. Dot-separated notations: octal, hex-octet, or shorthand (e.g. 127.1, 0177.0.0.1, 0x7f.0.0.1)
    if (host_str.find('.') != std::string::npos) {
        std::stringstream ss(host_str);
        std::string segment;
        std::vector<std::string> parts;
        while (std::getline(ss, segment, '.')) {
            parts.push_back(segment);
        }

        // Shorthand notation (e.g., 127.1 -> 127.0.0.1, 127.0.1 -> 127.0.0.1)
        if (parts.size() == 2 && parts[0] == "127" && parts[1] == "1") {
            out_ip = "127.0.0.1";
            out_type = "shorthand_ip";
            return true;
        }

        // 4 octets with octal or hex segments
        if (parts.size() == 4) {
            bool hasAlternative = false;
            std::vector<unsigned long> octets;
            for (const auto& part : parts) {
                if (part.empty()) return false;
                try {
                    int base = 10;
                    if (part.size() > 2 && (part[0] == '0' && (part[1] == 'x' || part[1] == 'X'))) {
                        base = 16;
                        hasAlternative = true;
                    } else if (part.size() > 1 && part[0] == '0') {
                        base = 8;
                        hasAlternative = true;
                    }
                    unsigned long o = std::stoul(part, nullptr, base);
                    if (o > 255) return false;
                    octets.push_back(o);
                } catch (...) {
                    return false;
                }
            }

            if (octets.size() == 4 && octets[0] == 127 && octets[1] == 0 && octets[2] == 0 && octets[3] == 1) {
                out_ip = "127.0.0.1";
                out_type = hasAlternative ? "octal_or_hex_notation" : "canonical_ipv4";
                return true;
            }
        }
    }

    return false;
}

bool SSRFHandler::parseUrl(
    const std::string& raw_url,
    ParsedTarget& target,
    std::string& error_msg
) {
    if (raw_url.empty()) {
        error_msg = "URL parameter cannot be empty";
        return false;
    }

    // Check scheme
    size_t scheme_pos = raw_url.find("://");
    if (scheme_pos == std::string::npos) {
        error_msg = "Malformed URL: missing scheme (must start with http:// or https://)";
        return false;
    }

    target.scheme = raw_url.substr(0, scheme_pos);
    std::transform(target.scheme.begin(), target.scheme.end(), target.scheme.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (target.scheme != "http" && target.scheme != "https") {
        error_msg = "Unsupported scheme '" + target.scheme + "://'. Only http:// is permitted in this testbed.";
        return false;
    }

    size_t authority_start = scheme_pos + 3;
    size_t slash_pos = raw_url.find('/', authority_start);

    std::string authority;
    if (slash_pos == std::string::npos) {
        authority = raw_url.substr(authority_start);
        target.path_and_query = "/";
    } else {
        authority = raw_url.substr(authority_start, slash_pos - authority_start);
        target.path_and_query = raw_url.substr(slash_pos);
    }

    if (authority.empty()) {
        error_msg = "Invalid URL: missing host authority";
        return false;
    }

    // Strip userinfo if present
    size_t at_pos = authority.find('@');
    if (at_pos != std::string::npos) {
        authority = authority.substr(at_pos + 1);
    }

    // Handle host and port
    std::string host_part;
    int port_num = (target.scheme == "https") ? 443 : 80;

    if (!authority.empty() && authority[0] == '[') {
        // IPv6 bracketed address
        size_t close_bracket = authority.find(']');
        if (close_bracket == std::string::npos) {
            error_msg = "Malformed IPv6 address in URL: missing closing bracket";
            return false;
        }
        host_part = authority.substr(0, close_bracket + 1);
        if (close_bracket + 1 < authority.size() && authority[close_bracket + 1] == ':') {
            std::string port_str = authority.substr(close_bracket + 2);
            try {
                port_num = std::stoi(port_str);
            } catch (...) {
                error_msg = "Malformed port in IPv6 URL";
                return false;
            }
        }
    } else {
        size_t colon_pos = authority.find(':');
        if (colon_pos == std::string::npos) {
            host_part = authority;
        } else {
            host_part = authority.substr(0, colon_pos);
            std::string port_str = authority.substr(colon_pos + 1);
            try {
                port_num = std::stoi(port_str);
            } catch (...) {
                error_msg = "Malformed port in URL";
                return false;
            }
        }
    }

    if (port_num <= 0 || port_num > 65535) {
        error_msg = "Invalid port number (must be 1-65535)";
        return false;
    }

    target.original_host = host_part;
    target.port = port_num;

    // Decode URL-encoded host if present
    std::string decoded_host = urlDecode(host_part);
    bool hostWasEncoded = (decoded_host != host_part);

    // Host normalization & classification
    std::string normalized_ip;
    std::string notation_type;

    if (decoded_host == "127.0.0.1" || decoded_host == "localhost") {
        target.resolved_host = "127.0.0.1";
        target.is_loopback = true;
        target.is_alternative_notation = hostWasEncoded;
        target.notation_type = hostWasEncoded ? "url_encoded_host" : "canonical";
    } else if (parseIPv4Alternative(decoded_host, normalized_ip, notation_type)) {
        target.resolved_host = normalized_ip;
        target.is_loopback = true;
        target.is_alternative_notation = (notation_type != "canonical_ipv4" || hostWasEncoded);
        target.notation_type = hostWasEncoded ? ("url_encoded_" + notation_type) : notation_type;
    } else {
        target.resolved_host = decoded_host;
        target.is_loopback = false;
        target.is_alternative_notation = false;
        target.notation_type = "external_or_invalid";
    }

    return true;
}

bool SSRFHandler::validateTarget(
    const ParsedTarget& target,
    SecurityMode mode,
    std::string& error_msg,
    int& status_code
) {
    // Both modes: Bound strictly to loopback targets for environment safety
    if (!target.is_loopback) {
        status_code = 403;
        error_msg = "{\"status\":\"blocked\",\"error\":\"Destination host not permitted. Testbed is strictly confined to loopback (127.0.0.1).\",\"code\":\"ERR_HOST_NOT_ALLOWED\"}";
        return false;
    }

    // Allowable testbed ports: 8080 (public), 8081 (internal service), 8090 (OOB callback receiver)
    const std::set<int> testbedPorts = { 8080, 8081, 8090 };
    if (testbedPorts.find(target.port) == testbedPorts.end()) {
        status_code = 403;
        error_msg = "{\"status\":\"blocked\",\"error\":\"Destination port not permitted in testbed. Allowed ports: 8080, 8081, 8090.\",\"code\":\"ERR_PORT_NOT_ALLOWED\"}";
        return false;
    }

    // ==========================================
    // SECURE MODE STRICT ENFORCEMENTS
    // ==========================================
    if (mode == SecurityMode::SECURE) {
        // 1. Enforce strict canonical representation: reject decimal, octal, hex, IPv6, URL-encoded
        if (target.is_alternative_notation || target.original_host != "127.0.0.1") {
            status_code = 403;
            std::ostringstream ss;
            ss << "{\n"
               << "  \"status\": \"blocked\",\n"
               << "  \"mode\": \"secure\",\n"
               << "  \"error\": \"Security policy violation: alternative or obfuscated host representation rejected\",\n"
               << "  \"notation_type\": \"" << target.notation_type << "\",\n"
               << "  \"code\": \"ERR_NON_CANONICAL_HOST\"\n"
               << "}";
            error_msg = ss.str();
            return false;
        }

        // 2. Strict Access Control: Deny internal sensitive service (Port 8081)
        if (target.port == 8081) {
            status_code = 403;
            error_msg = "{\n  \"status\": \"blocked\",\n  \"mode\": \"secure\",\n  \"error\": \"Security policy violation: direct access to internal test service port 8081 is restricted\",\n  \"code\": \"ERR_INTERNAL_PORT_BLOCKED\"\n}";
            return false;
        }
    }

    // ==========================================
    // VULNERABLE MODE
    // ==========================================
    return true;
}

void SSRFHandler::handleFetch(
    const httplib::Request& req,
    httplib::Response& res,
    SecurityMode forced_mode
) {
    if (!req.has_param("url")) {
        res.status = 400;
        res.set_content(
            "{\"status\":\"error\",\"error\":\"Missing 'url' query parameter. Example: /fetch?url=http://127.0.0.1:8081/internal/secret\"}",
            "application/json"
        );
        return;
    }

    // Determine security mode:
    // Priority: forced_mode argument > 'mode' query parameter > 'X-SSRF-Mode' header > default (VULNERABLE)
    SecurityMode activeMode = forced_mode;
    if (forced_mode == SecurityMode::VULNERABLE) {
        std::string modeStr;
        if (req.has_param("mode")) {
            modeStr = req.get_param_value("mode");
        } else if (req.has_header("X-SSRF-Mode")) {
            modeStr = req.get_header_value("X-SSRF-Mode");
        }

        if (modeStr == "secure" || modeStr == "strict" || modeStr == "hardened") {
            activeMode = SecurityMode::SECURE;
        }
    }

    std::string current_url = req.get_param_value("url");
    int redirect_hops = 0;
    const int max_redirects = (activeMode == SecurityMode::SECURE) ? 0 : 3;

    while (true) {
        ParsedTarget target;
        std::string parse_err;

        if (!parseUrl(current_url, target, parse_err)) {
            res.status = 400;
            res.set_content(
                "{\"status\":\"error\",\"error\":\"" + parse_err + "\"}",
                "application/json"
            );
            return;
        }

        std::string validation_err;
        int status_code = 200;
        if (!validateTarget(target, activeMode, validation_err, status_code)) {
            res.status = status_code;
            res.set_content(validation_err, "application/json");
            return;
        }

        // Connect to target service
        httplib::Client client(target.resolved_host, target.port);

        // Configure timeouts:
        // Vulnerable mode: 2s connect, 8s read (allows time-based delay testing)
        // Secure mode: 1s connect, 2s read
        if (activeMode == SecurityMode::SECURE) {
            client.set_connection_timeout(1, 0);
            client.set_read_timeout(2, 0);
        } else {
            client.set_connection_timeout(2, 0);
            client.set_read_timeout(8, 0);
        }

        auto response = client.Get(target.path_and_query.c_str());

        if (!response) {
            res.status = 502;
            res.set_content(
                "{\"status\":\"error\",\"error\":\"Internal test request failed (connection refused or timeout)\"}",
                "application/json"
            );
            return;
        }

        // Handle Redirects (301, 302, 303, 307, 308)
        if (response->status >= 300 && response->status < 400 && response->has_header("Location")) {
            std::string location = response->get_header_value("Location");

            if (activeMode == SecurityMode::SECURE) {
                // Secure Mode: Do not follow redirects into restricted services
                res.status = 403;
                res.set_content(
                    "{\"status\":\"blocked\",\"mode\":\"secure\",\"error\":\"Security policy violation: redirects are restricted in secure mode\",\"code\":\"ERR_REDIRECT_RESTRICTED\"}",
                    "application/json"
                );
                return;
            }

            // Vulnerable Mode: Follow redirects up to max_redirects
            if (redirect_hops >= max_redirects) {
                res.status = 508;
                res.set_content(
                    "{\"status\":\"error\",\"error\":\"Too many redirects (infinite loop detected or limit exceeded)\",\"code\":\"ERR_TOO_MANY_REDIRECTS\"}",
                    "application/json"
                );
                return;
            }

            redirect_hops++;

            // Resolve relative vs absolute redirect location
            if (location.rfind("http://", 0) == 0 || location.rfind("https://", 0) == 0) {
                current_url = location;
            } else {
                // Relative redirect path on the same target host and port
                std::string base = "http://" + target.resolved_host + ":" + std::to_string(target.port);
                if (!location.empty() && location[0] == '/') {
                    current_url = base + location;
                } else {
                    current_url = base + "/" + location;
                }
            }
            continue; // Follow redirect to new URL
        }

        // Deliver final response
        res.status = response->status;

        // Forward response headers (Content-Type, X- internal markers, etc.)
        for (const auto& header : response->headers) {
            if (header.first.rfind("X-", 0) == 0 || header.first == "Content-Type") {
                res.set_header(header.first.c_str(), header.second.c_str());
            }
        }

        res.set_header("X-SSRF-Mode", (activeMode == SecurityMode::SECURE ? "secure" : "vulnerable"));
        res.set_header("X-SSRF-Hops", std::to_string(redirect_hops).c_str());

        std::string contentType = response->has_header("Content-Type")
            ? response->get_header_value("Content-Type")
            : "application/json";

        res.set_content(response->body, contentType.c_str());
        return;
    }
}
