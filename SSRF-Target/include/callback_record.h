#ifndef SSRF_SENTINEL_CALLBACK_RECORD_H
#define SSRF_SENTINEL_CALLBACK_RECORD_H

#include <string>
#include <vector>
#include <set>
#include <mutex>
#include <cstdint>

struct CallbackEvent {
    uint64_t id;
    std::string token;
    std::string timestamp;
    std::string method;
    std::string path;
    std::string source_ip;
};

class CallbackStore {
private:
    mutable std::mutex mutex_;
    std::vector<CallbackEvent> events_;
    std::set<std::string> registered_tokens_;
    uint64_t next_id_;

    static std::string getCurrentIsoTimestamp();
    static std::string generateRandomHex(size_t length);

public:
    CallbackStore();

    // Token management
    std::string generateToken();
    bool isTokenRegistered(const std::string& token) const;

    // Callback event recording
    uint64_t recordEvent(
        const std::string& token,
        const std::string& method,
        const std::string& path,
        const std::string& source_ip
    );

    // Evidence retrieval (JSON format)
    std::string getEvidenceJson(const std::string& token = "") const;

    // Management & verification
    size_t count(const std::string& token = "") const;
    void clear();
};

#endif // SSRF_SENTINEL_CALLBACK_RECORD_H

