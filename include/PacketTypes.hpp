#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <chrono>

namespace nids {

enum class Protocol : uint8_t {
    ICMP = 1,
    TCP  = 6,
    UDP  = 17,
    UNKNOWN = 255
};

enum class AlertSeverity {
    INFO,
    MEDIUM,
    HIGH,
    CRITICAL
};

struct ParsedPacket {
    std::chrono::system_clock::time_point timestamp;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port{0};
    uint16_t dst_port{0};
    Protocol protocol{Protocol::UNKNOWN};
    uint8_t tcp_flags{0};
    bool is_syn{false};
    bool is_ack{false};
    bool is_fin{false};
    bool is_rst{false};
    std::vector<uint8_t> payload;
    size_t wire_length{0};
};

struct Alert {
    std::chrono::system_clock::time_point timestamp;
    AlertSeverity severity;
    std::string signature_name;
    std::string description;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
};

} // namespace nids