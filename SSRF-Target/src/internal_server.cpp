#include "internal_server.h"
#include "internal_service.h"

#include <iostream>
#include <stdexcept>
#include <thread>
#include <chrono>
#include <algorithm>

void InternalServer::registerRoutes() {

    // -------------------------------------------------------------
    // Baseline Endpoints (Preserved for compatibility)
    // -------------------------------------------------------------
    server.Get("/internal/status",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.set_content(
                InternalService::getStatus(),
                "application/json"
            );
        }
    );

    server.Get("/internal/secret",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.set_header("X-Internal-Service", "SSRF-Sentinel-Mock");
            res.set_content(
                InternalService::getSecret(),
                "application/json"
            );
        }
    );

    // -------------------------------------------------------------
    // Category A: In-Band / Content-Based SSRF
    // -------------------------------------------------------------
    server.Get("/internal/admin/config",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.set_header("X-Internal-Service", "SSRF-Sentinel-Core");
            res.set_header("X-Resource-ID", "admin-config-vault");
            res.set_content(
                InternalService::getAdminConfig(),
                "application/json"
            );
        }
    );

    // -------------------------------------------------------------
    // Category B: Limited-Response SSRF
    // -------------------------------------------------------------
    // 1. Status-only response (HTTP 204 No Content with empty body)
    server.Get("/internal/limited/status-only",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.status = 204;
        }
    );

    // 2. Header-only response (HTTP 200 with headers but empty body)
    server.Get("/internal/limited/header-only",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.status = 200;
            res.set_header("X-Internal-Status", "ACTIVE");
            res.set_header("X-Response-Type", "HEADER_ONLY");
            res.set_header("X-Internal-Marker", "SSRF_HEADER_ONLY_FLAG");
            res.set_content("", "text/plain");
        }
    );

    // 3. Truncated response body
    server.Get("/internal/limited/truncated",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.status = 200;
            res.set_content(
                InternalService::getLimitedTruncated(),
                "application/json"
            );
        }
    );

    // 4. Generic success message (no internal metadata exposed)
    server.Get("/internal/limited/generic",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.status = 200;
            res.set_content(
                InternalService::getLimitedGeneric(),
                "application/json"
            );
        }
    );

    // 5. Internal content suppressed by policy filter
    server.Get("/internal/limited/suppressed",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.status = 200;
            res.set_content(
                InternalService::getLimitedSuppressed(),
                "application/json"
            );
        }
    );

    // -------------------------------------------------------------
    // Category C: Time-Based SSRF
    // -------------------------------------------------------------
    // Fast baseline endpoint (< 1ms execution)
    server.Get("/internal/fast",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.set_content(
                InternalService::getFastResponse(),
                "application/json"
            );
        }
    );

    // Bounded delayed endpoint
    server.Get("/internal/delayed",
        [](const httplib::Request& req, httplib::Response& res) {
            int delay_ms = 2000; // Default: 2 seconds

            if (req.has_param("delay")) {
                try {
                    int sec = std::stoi(req.get_param_value("delay"));
                    delay_ms = sec * 1000;
                } catch (...) {}
            } else if (req.has_param("ms")) {
                try {
                    delay_ms = std::stoi(req.get_param_value("ms"));
                } catch (...) {}
            }

            // Enforce safe bounds: 0 to 5000 ms to avoid indefinite blocking
            delay_ms = std::max(0, std::min(delay_ms, 5000));

            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));

            res.set_content(
                InternalService::getDelayedResponse(delay_ms),
                "application/json"
            );
        }
    );

    // -------------------------------------------------------------
    // Category D: Boolean-Based SSRF
    // -------------------------------------------------------------
    server.Get("/internal/check",
        [](const httplib::Request& req, httplib::Response& res) {
            if (!req.has_param("condition")) {
                res.status = 400;
                res.set_content(
                    R"({"error":"Missing required 'condition' query parameter. Example: /internal/check?condition=true"})",
                    "application/json"
                );
                return;
            }

            std::string condition = req.get_param_value("condition");

            if (condition == "true" || condition == "1") {
                // Condition TRUE: Status 200, large body length, header TRUE
                res.status = 200;
                res.set_header("X-SSRF-Evaluation", "TRUE");
                res.set_content(
                    InternalService::getCheckTrue(),
                    "application/json"
                );
            } else if (condition == "false" || condition == "0") {
                // Condition FALSE: Status 404, small body length, header FALSE
                res.status = 404;
                res.set_header("X-SSRF-Evaluation", "FALSE");
                res.set_content(
                    InternalService::getCheckFalse(),
                    "application/json"
                );
            } else {
                res.status = 400;
                res.set_content(
                    R"({"error":"Invalid condition value. Expected 'true' or 'false'"})",
                    "application/json"
                );
            }
        }
    );

    // -------------------------------------------------------------
    // Category E: Redirect-Based SSRF Test Endpoints
    // -------------------------------------------------------------
    // Redirects client/SSRF proxy to a designated internal target
    server.Get("/internal/redirect",
        [](const httplib::Request& req, httplib::Response& res) {
            std::string target = "/internal/secret";
            if (req.has_param("to")) {
                target = req.get_param_value("to");
            } else if (req.has_param("target")) {
                target = req.get_param_value("target");
            }

            int code = 302;
            if (req.has_param("code")) {
                try {
                    int c = std::stoi(req.get_param_value("code"));
                    if (c == 301 || c == 302 || c == 303 || c == 307 || c == 308) {
                        code = c;
                    }
                } catch (...) {}
            }

            res.status = code;
            res.set_header("Location", target.c_str());
            res.set_header("X-Redirect-Target", target.c_str());
            res.set_content(
                InternalService::getRedirectNotice(target),
                "application/json"
            );
        }
    );

    // Redirect loop simulator: redirects back to itself to test redirect exhaustion
    server.Get("/internal/redirect-loop",
        [](const httplib::Request& req, httplib::Response& res) {
            (void)req;
            res.status = 302;
            res.set_header("Location", "http://127.0.0.1:8081/internal/redirect-loop");
            res.set_content(
                R"({"error":"Infinite redirect loop simulator"})",
                "application/json"
            );
        }
    );
}

void InternalServer::start() {
    registerRoutes();

    std::cout << "[INTERNAL SERVICE] Starting..." << std::endl;
    std::cout << "[INTERNAL SERVICE] Address: 127.0.0.1:8081" << std::endl;
    std::cout << "[INTERNAL SERVICE] Status: Running..." << std::endl;

    if (!server.listen("127.0.0.1", 8081)) {
        throw std::runtime_error(
            "Failed to start internal service on port 8081"
        );
    }
}

void InternalServer::stop() {
    server.stop();
}
