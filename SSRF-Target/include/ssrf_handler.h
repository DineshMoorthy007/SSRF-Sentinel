#ifndef SSRF_HANDLER_H
#define SSRF_HANDLER_H

#include "httplib.h"
#include <string>

enum class SecurityMode {
    VULNERABLE,
    SECURE
};

struct ParsedTarget {
    std::string scheme;
    std::string original_host;
    std::string resolved_host;
    int port;
    std::string path_and_query;
    bool is_loopback;
    bool is_alternative_notation;
    std::string notation_type;
};

class SSRFHandler {
public:
    static void handleFetch(
        const httplib::Request& req,
        httplib::Response& res,
        SecurityMode forced_mode = SecurityMode::VULNERABLE
    );

    static bool parseUrl(
        const std::string& raw_url,
        ParsedTarget& target,
        std::string& error_msg
    );

    static bool validateTarget(
        const ParsedTarget& target,
        SecurityMode mode,
        std::string& error_msg,
        int& status_code
    );

    static std::string urlDecode(const std::string& in);
    static bool parseIPv4Alternative(const std::string& host_str, std::string& out_ip, std::string& out_type);
};

#endif // SSRF_HANDLER_H
