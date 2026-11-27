#ifndef SSRF_SENTINEL_CALLBACK_RECORD_H
#define SSRF_SENTINEL_CALLBACK_RECORD_H

#include <string>
#include <vector>
#include <set>
#include <map>
#include <mutex>
#include <cstdint>

struct CallbackEvent {
    uint64_t id;
    std::string token;
    std::string timestamp;
    std::string method;
    std::string path;
    std::string source_ip;
    bool is_duplicate;
};

class CallbackStore {
private:
    mutable std::mutex mutex_;
    std::vector<CallbackEvent> events_;
    std::set<std::string> registered_tokens_;
    std::map<std::string, size_t> token_hit_counts_;
    uint64_t next_id_;

    static std::string getCurrentIsoTimestamp();
    static std::string generateRandomHex(size_t length);

public:
    CallbackStore();

    // Token management
    std::string generateToken();
    bool isTokenRegistered(const std::string& token) const;

    // Callback event recording with deduplication
    uint64_t recordEvent(
        const std::string& token,
        const std::string& method,
        const std::string& path,
        const std::string& source_ip
    );

    // Evidence retrieval (JSON format)
    std::string getEvidenceJson(const std::string& token = "") const;

    // Management & metrics
    size_t count(const std::string& token = "") const;
    size_t totalCount() const;
    size_t uniqueTokenCount() const;
    bool hasTokenReceived(const std::string& token) const;
    void clear();
};

#endif // SSRF_SENTINEL_CALLBACK_RECORD_H
