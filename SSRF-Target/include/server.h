#ifndef SSRF_SENTINEL_SERVER_H
#define SSRF_SENTINEL_SERVER_H

#include "httplib.h"

class ServerManager {
private:
    httplib::Server server;

    void registerRoutes();

public:
    void start();
    void stop();
};

#endif // SSRF_SENTINEL_SERVER_H
