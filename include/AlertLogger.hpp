#pragma once

#include "PacketTypes.hpp"
#include <mutex>
#include <string>

namespace nids {

class AlertLogger {
public:
    AlertLogger() = default;
    ~AlertLogger() = default;

    void log(const Alert& alert);

private:
    static std::string severity_to_string(AlertSeverity sev);
    static std::string format_iso_timestamp(const std::chrono::system_clock::time_point& tp);

    std::mutex log_mutex_;
};

} // namespace nids