#include "callback_server.h"

#include <iostream>
#include <stdexcept>

CallbackServer::CallbackServer() {}

void CallbackServer::registerRoutes() {

    // 1. Health check
    server.Get("/health", [](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        res.set_content(
            R"({"status":"running","service":"SSRF Callback Receiver","port":8090})",
            "application/json"
        );
    });

    // 2. Token generation endpoint
    auto generateTokenHandler = [this](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        std::string token = store.generateToken();
        std::string json = "{\n"
                           "  \"status\": \"success\",\n"
                           "  \"token\": \"" + token + "\",\n"
                           "  \"callback_url\": \"http://127.0.0.1:8090/callback?token=" + token + "\"\n"
                           "}";
        res.set_content(json, "application/json");
    };

    server.Get("/token/generate", generateTokenHandler);
    server.Post("/token/generate", generateTokenHandler);

    // 3. Callback receiver endpoint: accepts GET, POST, HEAD, PUT
    auto callbackHandler = [this](const httplib::Request& req, httplib::Response& res) {
        std::string token;
        if (req.has_param("token")) {
            token = req.get_param_value("token");
        } else if (req.path.rfind("/callback/", 0) == 0 && req.path.size() > 10) {
            token = req.path.substr(10);
        }

        std::string fullPath = req.path;
        if (!req.params.empty()) {
            fullPath += "?";
            bool first = true;
            for (const auto& p : req.params) {
                if (!first) fullPath += "&";
                fullPath += p.first + "=" + p.second;
                first = false;
            }
        }

        uint64_t id = store.recordEvent(token, req.method, fullPath, req.remote_addr);

        std::cout << "[OOB CALLBACK] Received " << req.method << " request (ID #" << id
                  << ", Token: " << (token.empty() ? "(none)" : token)
                  << ") from " << req.remote_addr << std::endl;

        // NOTE: We deliberately do NOT return callback evidence or internal details in this response!
        res.status = 200;
        res.set_content(
            R"({"status":"received","message":"Callback acknowledged"})",
            "application/json"
        );
    };

    server.Get("/callback", callbackHandler);
    server.Post("/callback", callbackHandler);
    server.Get(R"(/callback/(.+))", callbackHandler);
    server.Post(R"(/callback/(.+))", callbackHandler);

    // 4. Evidence retrieval endpoint for the scanner
    server.Get("/evidence", [this](const httplib::Request& req, httplib::Response& res) {
        std::string token;
        if (req.has_param("token")) {
            token = req.get_param_value("token");
        }
        res.set_content(store.getEvidenceJson(token), "application/json");
    });

    // 5. Evidence reset endpoint
    auto resetHandler = [this](const httplib::Request& req, httplib::Response& res) {
        (void)req;
        store.clear();
        std::cout << "[OOB CALLBACK] Evidence store reset." << std::endl;
        res.set_content(
            R"({"status":"cleared","message":"All callback evidence cleared"})",
            "application/json"
        );
    };

    server.Post("/evidence/reset", resetHandler);
    server.Delete("/evidence", resetHandler);
}

void CallbackServer::start() {
    registerRoutes();

    std::cout << "[OOB CALLBACK] Starting..." << std::endl;
    std::cout << "[OOB CALLBACK] Address: 127.0.0.1:8090" << std::endl;
    std::cout << "[OOB CALLBACK] Status: Running..." << std::endl;

    if (!server.listen("127.0.0.1", 8090)) {
        throw std::runtime_error("Failed to start OOB callback server on port 8090");
    }
}

void CallbackServer::stop() {
    server.stop();
}

