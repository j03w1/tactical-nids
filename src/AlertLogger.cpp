#include "AlertLogger.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>

namespace nids {

std::string AlertLogger::severity_to_string(AlertSeverity sev) {
    switch (sev) {
        case AlertSeverity::INFO:     return "INFO";
        case AlertSeverity::MEDIUM:   return "MEDIUM";
        case AlertSeverity::HIGH:     return "HIGH";
        case AlertSeverity::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

std::string AlertLogger::format_iso_timestamp(const std::chrono::system_clock::time_point& tp) {
    auto time_t_val = std::chrono::system_clock::to_time_t(tp);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t_val), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

void AlertLogger::log(const Alert& alert) {
    std::lock_guard<std::mutex> lock(log_mutex_);

    // Output structured JSON-formatted alerts for standard ingestion
    std::cout << "{\"timestamp\":\"" << format_iso_timestamp(alert.timestamp) << "\""
              << ",\"severity\":\"" << severity_to_string(alert.severity) << "\""
              << ",\"signature\":\"" << alert.signature_name << "\""
              << ",\"description\":\"" << alert.description << "\""
              << ",\"src\":\"" << alert.src_ip << ":" << alert.src_port << "\""
              << ",\"dst\":\"" << alert.dst_ip << ":" << alert.dst_port << "\"}\n"
              << std::flush;
}

} // namespace nids