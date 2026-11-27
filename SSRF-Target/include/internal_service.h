#ifndef INTERNAL_SERVICE_H
#define INTERNAL_SERVICE_H

#include <string>

class InternalService {
public:
    // Existing baseline endpoints
    static std::string getStatus();
    static std::string getSecret();

    // In-band / Content-based SSRF endpoints
    static std::string getAdminConfig();

    // Limited-Response SSRF endpoints
    static std::string getLimitedTruncated();
    static std::string getLimitedGeneric();
    static std::string getLimitedSuppressed();

    // Time-Based SSRF endpoints
    static std::string getFastResponse();
    static std::string getDelayedResponse(int delay_ms);

    // Boolean-Based SSRF endpoints
    static std::string getCheckTrue();
    static std::string getCheckFalse();

    // Redirect SSRF helpers
    static std::string getRedirectNotice(const std::string& target);
};

#endif // INTERNAL_SERVICE_H
