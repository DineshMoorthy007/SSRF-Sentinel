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
        input[type="url"], select { width: 50%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
        button { padding: 8px 16px; background: #d32f2f; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #b71c1c; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.8em; font-weight: bold; background: #e3f2fd; color: #0d47a1; }
        .badge-secure { background: #e8f5e9; color: #2e7d32; }
        .warning { background: #fff3e0; border-left: 4px solid #ff9800; padding: 10px; margin: 15px 0; }
        table { border-collapse: collapse; width: 100%; margin-top: 15px; }
        th, td { text-align: left; padding: 8px 12px; border: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
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
            <input type="text" id="urlInput" name="url" value="http://127.0.0.1:8081/internal/secret" style="width:60%; padding:8px;" required><br><br>
            <label for="modeSelect">Security Mode:</label><br><br>
            <select id="modeSelect" name="mode">
                <option value="vulnerable" selected>Vulnerable (allows redirects, alternative IP representations, internal access)</option>
                <option value="secure">Secure (strict allowlist, blocks port 8081, blocks redirects)</option>
            </select><br><br>
            <button type="submit">Fetch URL</button>
        </form>
    </div>

    <h2>SSRF Testing Scenarios & Ground Truth Endpoints</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Endpoint</th>
            <th>Vulnerable Mode Behavior</th>
            <th>Secure Mode Behavior</th>
        </tr>
        <tr>
            <td><span class="badge">In-Band</span></td>
            <td><code>/internal/secret</code></td>
            <td>Returns HTTP 200 with secret marker</td>
            <td>Blocked (HTTP 403 Forbidden)</td>
        </tr>
        <tr>
            <td><span class="badge">In-Band</span></td>
            <td><code>/internal/admin/config</code></td>
            <td>Returns HTTP 200 with credentials</td>
            <td>Blocked (HTTP 403 Forbidden)</td>
        </tr>
        <tr>
            <td><span class="badge">Limited</span></td>
            <td><code>/internal/limited/status-only</code></td>
            <td>HTTP 204 No Content</td>
            <td>Blocked (HTTP 403 Forbidden)</td>
        </tr>
        <tr>
            <td><span class="badge">Limited</span></td>
            <td><code>/internal/limited/header-only</code></td>
            <td>HTTP 200 with headers only</td>
            <td>Blocked (HTTP 403 Forbidden)</td>
        </tr>
        <tr>
            <td><span class="badge">Time-Based</span></td>
            <td><code>/internal/delayed?ms=2000</code></td>
            <td>Deterministic ~2.0s delay</td>
            <td>Blocked (HTTP 403 Forbidden)</td>
        </tr>
        <tr>
            <td><span class="badge">Boolean</span></td>
            <td><code>/internal/check?condition=true|false</code></td>
            <td>200 (True) vs 404 (False) differential</td>
            <td>Blocked (HTTP 403 Forbidden)</td>
        </tr>
        <tr>
            <td><span class="badge">Blind / OOB</span></td>
            <td><code>http://127.0.0.1:8090/callback?token=...</code></td>
            <td>Recorded in OOB store</td>
            <td>Recorded if authorized, otherwise blocked</td>
        </tr>
        <tr>
            <td><span class="badge">Redirect</span></td>
            <td><code>/internal/redirect?to=...</code></td>
            <td>Follows redirect up to 3 hops</td>
            <td>Redirect rejected (HTTP 403)</td>
        </tr>
        <tr>
            <td><span class="badge">URL Bypass</span></td>
            <td><code>http://2130706433:8081/internal/secret</code></td>
            <td>Normalized & accepted (exposes secret)</td>
            <td>Blocked (HTTP 403 non-canonical host)</td>
        </tr>
    </table>

    <hr>
    <p>
        <a href="/health">Public Health Endpoint</a> | 
        <a href="http://127.0.0.1:8090/health">OOB Health Endpoint</a> | 
        <a href="http://127.0.0.1:8090/evidence">OOB Evidence Store</a>
    </p>
</body>
</html>)";
        res.set_content(html, "text/html");
    });

    // Public health endpoint
    server.Get("/health", [](const httplib::Request& req,
                             httplib::Response& res) {
        (void)req;
        res.set_content(
            R"({"status":"running","service":"Public Application","port":8080})",
            "application/json"
        );
    });

    // SSRF endpoint (configurable mode via query parameter or header)
    server.Get("/fetch", [](const httplib::Request& req,
                            httplib::Response& res) {
        SSRFHandler::handleFetch(req, res);
    });

    // Hardened SSRF endpoint (forces Secure Mode)
    server.Get("/fetch-secure", [](const httplib::Request& req,
                                   httplib::Response& res) {
        SSRFHandler::handleFetch(req, res, SecurityMode::SECURE);
    });

    // Public open redirect test simulator
    server.Get("/redirect", [](const httplib::Request& req,
                               httplib::Response& res) {
        std::string target = "/health";
        if (req.has_param("to")) {
            target = req.get_param_value("to");
        } else if (req.has_param("target")) {
            target = req.get_param_value("target");
        }

        res.status = 302;
        res.set_header("Location", target.c_str());
        res.set_content(
            "{\"status\":\"redirect\",\"target\":\"" + target + "\"}",
            "application/json"
        );
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
