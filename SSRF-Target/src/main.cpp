#include "server.h"
#include "internal_server.h"
#include "callback_server.h"

#include <iostream>
#include <thread>
#include <chrono>
#include <atomic>
#include <csignal>
#include <functional>

namespace {
    std::function<void()> g_shutdownHandler;

    void signalHandler(int sig) {
        (void)sig;
        if (g_shutdownHandler) {
            g_shutdownHandler();
        }
    }
}

int main() {
    try {
        std::cout << "\n========================================================" << std::endl;
        std::cout << "         SSRF SENTINEL - ADVANCED TARGET LAB            " << std::endl;
        std::cout << "========================================================" << std::endl;
        std::cout << "[SECURITY NOTICE] All services bind exclusively to loopback (127.0.0.1)." << std::endl;
        std::cout << "                  Loopback binding does not provide process isolation" << std::endl;
        std::cout << "                  from other local processes on this host." << std::endl;
        std::cout << "--------------------------------------------------------" << std::endl;

        ServerManager publicServer;
        InternalServer internalServer;
        CallbackServer callbackServer;

        std::atomic<bool> isShuttingDown{false};

        auto performShutdown = [&]() {
            bool expected = false;
            if (!isShuttingDown.compare_exchange_strong(expected, true)) {
                return;
            }
            std::cout << "\n[SHUTDOWN] Stopping all servers gracefully..." << std::endl;
            publicServer.stop();
            internalServer.stop();
            callbackServer.stop();
        };

        g_shutdownHandler = performShutdown;
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);

        // 1. Start Internal Service (Port 8081) in dedicated thread
        std::thread internalThread([&internalServer, &isShuttingDown]() {
            try {
                internalServer.start();
            } catch (const std::exception& e) {
                if (!isShuttingDown) {
                    std::cerr << "\n[INTERNAL SERVER ERROR] " << e.what() << std::endl;
                }
            }
        });

        // 2. Start OOB Callback Server (Port 8090) in dedicated thread
        std::thread callbackThread([&callbackServer, &isShuttingDown]() {
            try {
                callbackServer.start();
            } catch (const std::exception& e) {
                if (!isShuttingDown) {
                    std::cerr << "\n[CALLBACK SERVER ERROR] " << e.what() << std::endl;
                }
            }
        });

        // Allow background services to initialize sockets
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        // 3. Start Public Application (Port 8080) in dedicated thread
        std::thread publicThread([&publicServer, &isShuttingDown]() {
            try {
                publicServer.start();
            } catch (const std::exception& e) {
                if (!isShuttingDown) {
                    std::cerr << "\n[PUBLIC SERVER ERROR] " << e.what() << std::endl;
                }
            }
        });

        // Allow public server to start
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        std::cout << "\n========================================================" << std::endl;
        std::cout << "              ACTIVE SERVICES & PORTS                   " << std::endl;
        std::cout << "========================================================" << std::endl;
        std::cout << " 1. Public App         : http://127.0.0.1:8080" << std::endl;
        std::cout << "    - GET /            : Web UI / SSRF Test form" << std::endl;
        std::cout << "    - GET /health      : Public health status" << std::endl;
        std::cout << "    - GET /fetch?url=  : SSRF proxy (mode=vulnerable|secure)" << std::endl;
        std::cout << "    - GET /fetch-secure: Hardened SSRF proxy (secure mode only)" << std::endl;
        std::cout << "    - GET /redirect?to=: Open redirect simulator" << std::endl;
        std::cout << " 2. Internal Service   : http://127.0.0.1:8081" << std::endl;
        std::cout << "    - In-Band          : /internal/status, /internal/secret, /internal/admin/config" << std::endl;
        std::cout << "    - Limited-Response : /internal/limited/status-only, header-only, truncated, generic, suppressed" << std::endl;
        std::cout << "    - Time-Based       : /internal/fast, /internal/delayed?ms=2000" << std::endl;
        std::cout << "    - Boolean-Based    : /internal/check?condition=true|false" << std::endl;
        std::cout << "    - Redirect SSRF    : /internal/redirect?to=..., /internal/redirect-loop" << std::endl;
        std::cout << " 3. OOB Receiver       : http://127.0.0.1:8090" << std::endl;
        std::cout << "    - GET/POST /token/generate" << std::endl;
        std::cout << "    - GET/POST /callback?token=<tok>" << std::endl;
        std::cout << "    - GET /evidence?token=<tok>" << std::endl;
        std::cout << "    - POST /evidence/reset" << std::endl;
        std::cout << "========================================================" << std::endl;
        std::cout << "[TARGET READY] Listening for requests. Press Ctrl+C to terminate." << std::endl;

        // Join server threads
        if (publicThread.joinable()) publicThread.join();
        if (internalThread.joinable()) internalThread.join();
        if (callbackThread.joinable()) callbackThread.join();

    } catch (const std::exception& e) {
        std::cerr << "[FATAL ERROR] " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
