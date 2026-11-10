#include "callback_record.h"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <random>
#include <ctime>

CallbackStore::CallbackStore() : next_id_(1) {}

std::string CallbackStore::getCurrentIsoTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t tt = std::chrono::system_clock::to_time_t(now);
    std::tm gmt;
#if defined(_WIN32)
    gmtime_s(&gmt, &tt);
#else
    gmtime_r(&tt, &gmt);
#endif
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()
    ) % 1000;

    std::ostringstream ss;
    ss << std::put_time(&gmt, "%Y-%m-%dT%H:%M:%S")
       << '.' << std::setfill('0') << std::setw(3) << ms.count()
       << 'Z';
    return ss.str();
}

std::string CallbackStore::generateRandomHex(size_t length) {
    static const char hexChars[] = "0123456789abcdef";
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, 15);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result.push_back(hexChars[dis(gen)]);
    }
    return result;
}

std::string CallbackStore::generateToken() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string token = "ssrf_tok_" + generateRandomHex(16);
    registered_tokens_.insert(token);
    return token;
}

bool CallbackStore::isTokenRegistered(const std::string& token) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return registered_tokens_.find(token) != registered_tokens_.end();
}

uint64_t CallbackStore::recordEvent(
    const std::string& token,
    const std::string& method,
    const std::string& path,
    const std::string& source_ip
) {
    std::lock_guard<std::mutex> lock(mutex_);
    CallbackEvent ev;
    ev.id = next_id_++;
    ev.token = token.empty() ? "anonymous" : token;
    ev.timestamp = getCurrentIsoTimestamp();
    ev.method = method;
    ev.path = path;
    ev.source_ip = source_ip;

    events_.push_back(ev);
    return ev.id;
}

static std::string escapeJson(const std::string& input) {
    std::ostringstream ss;
    for (char c : input) {
        if (c == '"') ss << "\\\"";
        else if (c == '\\') ss << "\\\\";
        else if (c == '\b') ss << "\\b";
        else if (c == '\f') ss << "\\f";
        else if (c == '\n') ss << "\\n";
        else if (c == '\r') ss << "\\r";
        else if (c == '\t') ss << "\\t";
        else ss << c;
    }
    return ss.str();
}

std::string CallbackStore::getEvidenceJson(const std::string& token) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream ss;

    std::vector<const CallbackEvent*> matches;
    for (const auto& ev : events_) {
        if (token.empty() || ev.token == token) {
            matches.push_back(&ev);
        }
    }

    ss << "{\n";
    ss << "  \"service\": \"SSRF Callback Evidence Store\",\n";
    ss << "  \"filter_token\": \"" << escapeJson(token) << "\",\n";
    ss << "  \"count\": " << matches.size() << ",\n";
    ss << "  \"callbacks\": [\n";

    for (size_t i = 0; i < matches.size(); ++i) {
        const auto* ev = matches[i];
        ss << "    {\n";
        ss << "      \"id\": " << ev->id << ",\n";
        ss << "      \"token\": \"" << escapeJson(ev->token) << "\",\n";
        ss << "      \"timestamp\": \"" << escapeJson(ev->timestamp) << "\",\n";
        ss << "      \"method\": \"" << escapeJson(ev->method) << "\",\n";
        ss << "      \"path\": \"" << escapeJson(ev->path) << "\",\n";
        ss << "      \"source_ip\": \"" << escapeJson(ev->source_ip) << "\"\n";
        ss << "    }" << (i + 1 < matches.size() ? "," : "") << "\n";
    }

    ss << "  ]\n";
    ss << "}";

    return ss.str();
}

size_t CallbackStore::count(const std::string& token) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (token.empty()) {
        return events_.size();
    }
    size_t cnt = 0;
    for (const auto& ev : events_) {
        if (ev.token == token) {
            cnt++;
        }
    }
    return cnt;
}

void CallbackStore::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.clear();
    registered_tokens_.clear();
    next_id_ = 1;
}

