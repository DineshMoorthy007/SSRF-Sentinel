#ifndef SSRF_HANDLER_H
#define SSRF_HANDLER_H

#include "httplib.h"
#include <string>

class SSRFHandler {
public:
    static void handleFetch(
        const httplib::Request& req,
        httplib::Response& res
    );

    static bool parseAndValidateUrl(
        const std::string& url,
        std::string& host,
        int& port,
        std::string& path_and_query,
        std::string& error_msg
    );
};

#endif // SSRF_HANDLER_H
