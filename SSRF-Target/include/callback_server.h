#ifndef SSRF_SENTINEL_CALLBACK_SERVER_H
#define SSRF_SENTINEL_CALLBACK_SERVER_H

#include "httplib.h"
#include "callback_record.h"

class CallbackServer {
private:
    httplib::Server server;
    CallbackStore store;

    void registerRoutes();

public:
    CallbackServer();

    void start();
    void stop();

    CallbackStore& getStore() { return store; }
};

#endif // SSRF_SENTINEL_CALLBACK_SERVER_H

