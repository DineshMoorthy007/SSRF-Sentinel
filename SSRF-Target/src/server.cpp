#include "server.h"
#include "ssrf_handler.h"

#include <iostream>
#include <stdexcept>

void ServerManager::registerRoutes() {

    // Public homepage with test interface and documentation
    server.Get("/", [](const httplib::Request& req,
                       httplib::Response& res) {
        (void)req;
        std::string html = R"(<!DOCTYPE html>
<html>
<head>
    <title>SSRF Sentinel Target - Advanced Testbed</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 30px; line-height: 1.6; color: #333; }
        h1 { color: #d32f2f; border-bottom: 2px solid #eee; padding-bottom: 10px; }
        h2 { color: #1976d2; margin-top: 25px; }
        .box { background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 6px; padding: 15px; margin-bottom: 20px; }
        code { background: #e8eaed; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
        input[type="url"] { width: 60%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 8px 16px; background: #d32f2f; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #b71c1c; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; background: #e3f2fd; color: #0d47a1; }
        .warning { background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 15px 0; }
    </style>
</head>
<body>
    <h1>SSRF Sentinel - Multi-Behavior Target Application</h1>
    <div class="warning">
        <strong>Security Notice:</strong> All services are bound strictly to loopback (127.0.0.1). Note that loopback binding does not provide OS-level isolation from other local processes on the same host.
    </div>

    <div class="box">
        <h2>Server-Side URL Fetcher (/fetch)</h2>
        <form action="/fetch" method="GET">
            <label for="urlInput">Enter Target URL:</label><br><br>
            <input type="url" id="urlInput" name="url" value="http://127.0.0.1:8081/internal/secret" required>
            <button type="submit">Fetch URL</button>
        </form>
    </div>

    <h2>Supported SSRF Testing Endpoints</h2>
    <ul>
        <li><span class="badge">In-Band</span> <code>http://127.0.0.1:8081/internal/secret</code> - Baseline secret resource</li>
        <li><span class="badge">In-Band</span> <code>http://127.0.0.1:8081/internal/admin/config</code> - Internal configuration vault</li>
        <li><span class="badge">Limited</span> <code>http://127.0.0.1:8081/internal/limited/status-only</code> - HTTP 204 No Content</li>
        <li><span class="badge">Limited</span> <code>http://127.0.0.1:8081/internal/limited/header-only</code> - HTTP 200 with headers only</li>
        <li><span class="badge">Limited</span> <code>http://127.0.0.1:8081/internal/limited/truncated</code> - Truncated response body</li>
        <li><span class="badge">Limited</span> <code>http://127.0.0.1:8081/internal/limited/generic</code> - Generic success message</li>
        <li><span class="badge">Limited</span> <code>http://127.0.0.1:8081/internal/limited/suppressed</code> - Policy-suppressed content</li>
        <li><span class="badge">Time-Based</span> <code>http://127.0.0.1:8081/internal/fast</code> - Immediate response (&lt;1ms)</li>
        <li><span class="badge">Time-Based</span> <code>http://127.0.0.1:8081/internal/delayed?ms=2000</code> - Bounded delayed response</li>
        <li><span class="badge">Boolean</span> <code>http://127.0.0.1:8081/internal/check?condition=true</code> - Evaluates condition</li>
        <li><span class="badge">Blind / OOB</span> <code>http://127.0.0.1:8090/callback?token=&lt;token&gt;</code> - Dedicated callback receiver</li>
    </ul>

    <hr>
    <p><a href="/health">Public Health Endpoint</a> | <a href="http://127.0.0.1:8090/health">OOB Health Endpoint</a></p>
</body>
</html>)";
        res.set_content(html, "text/html");
    });

    // Public health endpoint
    server.Get("/health", [](const httplib::Request& req,
                             httplib::Response& res) {
        (void)req;
        res.set_content(
            R"({"status":"running","service":"Public Application"})",
            "application/json"
        );
    });

    // SSRF endpoint
    server.Get("/fetch", [](const httplib::Request& req,
                            httplib::Response& res) {
        SSRFHandler::handleFetch(req, res);
    });
}

void ServerManager::start() {
    registerRoutes();

    std::cout << "[PUBLIC SERVER] Starting..." << std::endl;
    std::cout << "[PUBLIC SERVER] Address: 127.0.0.1:8080" << std::endl;
    std::cout << "[PUBLIC SERVER] Status: Running..." << std::endl;

    if (!server.listen("127.0.0.1", 8080)) {
        throw std::runtime_error(
            "Failed to start public server on port 8080"
        );
    }
}

void ServerManager::stop() {
    server.stop();
}
