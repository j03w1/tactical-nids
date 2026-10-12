#pragma once

#include "PacketTypes.hpp"
#include <unordered_map>
#include <set>
#include <chrono>
#include <string>
#include <vector>

namespace nids {

struct SignatureRule {
    std::string id;
    std::string name;
    AlertSeverity severity;
    std::string pattern;
    Protocol protocol;
    uint16_t target_port; // 0 matches any port
};

struct TrackerWindow {
    std::chrono::steady_clock::time_point window_start;
    std::set<uint16_t> unique_ports;
};

class DetectionEngine {
public:
    DetectionEngine();

    std::vector<Alert> evaluate(const ParsedPacket& packet);

private:
    void load_builtin_rules();
    std::vector<Alert> detect_signatures(const ParsedPacket& packet);
    std::vector<Alert> detect_port_scan(const ParsedPacket& packet);

    std::vector<SignatureRule> signatures_;
    std::unordered_map<std::string, TrackerWindow> scan_trackers_;

    // Port scan heuristic: 15 distinct ports scanned in 5 seconds
    static constexpr size_t SCAN_THRESHOLD = 15;
    static constexpr std::chrono::seconds SCAN_WINDOW{5};
};

} // namespace nids