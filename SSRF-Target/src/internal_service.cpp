#include "internal_service.h"

#include <sstream>

std::string InternalService::getStatus() {
    return R"({
  "service": "Internal Test Service",
  "status": "Running",
  "environment": "Local Testing"
})";
}

std::string InternalService::getSecret() {
    return R"({
  "resource": "Internal Test Resource",
  "classification": "Restricted",
  "verification_marker": "SSRF_SENTINEL_INTERNAL_ACCESS_2026"
})";
}

std::string InternalService::getAdminConfig() {
    return R"({
  "service": "Internal Admin Core",
  "version": "1.1-enterprise",
  "internal_network": "127.0.0.1/32",
  "database_uri": "postgresql://sentinel_admin:p@ssw0rd@127.0.0.1:5432/core_db",
  "admin_session_key": "ADMIN_KEY_784920193482",
  "verification_marker": "SSRF_SENTINEL_INBAND_FULL_ACCESS"
})";
}

std::string InternalService::getLimitedTruncated() {
    // Deliberately truncated JSON body simulating buffer cut-off / partial response
    return R"({"status":"success","leak":"SSRF_SECRET_SEGMENT_PARTIAL_DATA_REDA)";
}

std::string InternalService::getLimitedGeneric() {
    // Generic success message without any internal markers or sensitive tokens
    return R"({
  "status": "success",
  "message": "Internal request processed successfully"
})";
}

std::string InternalService::getLimitedSuppressed() {
    // Content filter suppression simulation
    return R"({
  "status": "acknowledged",
  "content_filter": "ACTIVE",
  "filtered_data": "[CONTENT_SUPPRESSED_BY_POLICY]"
})";
}

std::string InternalService::getFastResponse() {
    return R"({
  "endpoint": "/internal/fast",
  "status": "success",
  "delay_ms": 0,
  "execution": "immediate",
  "verification_marker": "SSRF_TIME_FAST_IMMEDIATE"
})";
}

std::string InternalService::getDelayedResponse(int delay_ms) {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"endpoint\": \"/internal/delayed\",\n"
       << "  \"status\": \"success\",\n"
       << "  \"delay_ms\": " << delay_ms << ",\n"
       << "  \"execution\": \"delayed\",\n"
       << "  \"verification_marker\": \"SSRF_TIME_DELAYED_SUCCESS\"\n"
       << "}";
    return ss.str();
}

std::string InternalService::getCheckTrue() {
    return R"({
  "endpoint": "/internal/check",
  "condition": true,
  "evaluation": "MATCH_TRUE",
  "result": "CONDITION_VERIFIED_SUCCESSFUL",
  "verification_marker": "SSRF_BOOLEAN_TRUE_VERIFIED",
  "padding": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
})";
}

std::string InternalService::getCheckFalse() {
    return R"({
  "endpoint": "/internal/check",
  "condition": false,
  "evaluation": "MATCH_FALSE"
})";
}

std::string InternalService::getRedirectNotice(const std::string& target) {
    std::ostringstream ss;
    ss << "{\n"
       << "  \"redirect\": true,\n"
       << "  \"target\": \"" << target << "\",\n"
       << "  \"verification_marker\": \"SSRF_REDIRECT_DISPATCHED\"\n"
       << "}";
    return ss.str();
}
