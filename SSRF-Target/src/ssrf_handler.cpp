#include "ssrf_handler.h"

#include <iostream>
#include <string>
#include <set>

bool SSRFHandler::parseAndValidateUrl(
    const std::string& url,
    std::string& host,
    int& port,
    std::string& path_and_query,
    std::string& error_msg
) {
    const std::string scheme = "http://";
    if (url.rfind(scheme, 0) != 0) {
        error_msg = "Only http:// scheme is permitted in local test environment";
        return false;
    }

    size_t authority_start = scheme.length();
    size_t slash_pos = url.find('/', authority_start);

    std::string authority;
    if (slash_pos == std::string::npos) {
        authority = url.substr(authority_start);
        path_and_query = "/";
    } else {
        authority = url.substr(authority_start, slash_pos - authority_start);
        path_and_query = url.substr(slash_pos);
    }

    if (authority.empty()) {
        error_msg = "Invalid URL: missing host authority";
        return false;
    }

    size_t colon_pos = authority.find(':');
    if (colon_pos == std::string::npos) {
        host = authority;
        port = 80;
    } else {
        host = authority.substr(0, colon_pos);
        std::string port_str = authority.substr(colon_pos + 1);
        try {
            port = std::stoi(port_str);
            if (port <= 0 || port > 65535) {
                error_msg = "Invalid port number";
                return false;
            }
        } catch (...) {
            error_msg = "Malformed port in URL";
            return false;
        }
    }

    // Explicit loopback destination allowlist
    const std::set<std::string> allowedHosts = { "127.0.0.1", "localhost" };
    if (allowedHosts.find(host) == allowedHosts.end()) {
        error_msg = "Destination host not permitted in local test environment (loopback only)";
        return false;
    }

    // Explicit authorized test service ports:
    // - 8080: Public application (self control test)
    // - 8081: Internal test service
    // - 8090: Dedicated OOB callback receiver
    const std::set<int> allowedPorts = { 8080, 8081, 8090 };
    if (allowedPorts.find(port) == allowedPorts.end()) {
        error_msg = "Destination port not permitted in local test environment (allowed: 8080, 8081, 8090)";
        return false;
    }

    return true;
}

void SSRFHandler::handleFetch(
    const httplib::Request& req,
    httplib::Response& res
) {
    if (!req.has_param("url")) {
        res.status = 400;
        res.set_content(
            "Missing URL parameter",
            "text/plain"
        );
        return;
    }

    std::string url = req.get_param_value("url");
    std::string host;
    int port = 0;
    std::string path_and_query;
    std::string error_msg;

    if (!parseAndValidateUrl(url, host, port, path_and_query, error_msg)) {
        res.status = 403;
        res.set_content(error_msg, "text/plain");
        return;
    }

    // Connect to authorized target test service
    httplib::Client client(host, port);

    // Bounded timeouts: connect 2s, read 8s (permits bounded delay endpoints up to 5s)
    client.set_connection_timeout(2, 0);
    client.set_read_timeout(8, 0);

    // Forward request
    auto response = client.Get(path_and_query.c_str());

    if (response) {
        res.status = response->status;

        // Forward response headers (Content-Type and any X- internal headers)
        for (const auto& header : response->headers) {
            if (header.first.rfind("X-", 0) == 0 || header.first == "Content-Type") {
                res.set_header(header.first.c_str(), header.second.c_str());
            }
        }

        std::string contentType = response->has_header("Content-Type")
            ? response->get_header_value("Content-Type")
            : "application/json";

        res.set_content(response->body, contentType.c_str());
    } else {
        res.status = 502;
        res.set_content(
            "Internal test request failed",
            "text/plain"
        );
    }
}
