#ifndef SSRF_SENTINEL_INTERNAL_SERVER_H
#define SSRF_SENTINEL_INTERNAL_SERVER_H

#include "httplib.h"

class InternalServer {
private:
    httplib::Server server;

    void registerRoutes();

public:
    void start();
    void stop();
};

#endif // SSRF_SENTINEL_INTERNAL_SERVER_H
