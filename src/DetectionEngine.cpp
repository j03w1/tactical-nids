#include "DetectionEngine.hpp"
#include <algorithm>

namespace nids {

DetectionEngine::DetectionEngine() {
    load_builtin_rules();
}

void DetectionEngine::load_builtin_rules() {
    signatures_ = {
        {
            "SIG-001",
            "Command Injection Attempt",
            AlertSeverity::CRITICAL,
            "/bin/sh",
            Protocol::TCP,
            0
        },
        {
            "SIG-002",
            "Directory Traversal Sequence",
            AlertSeverity::HIGH,
            "../../etc/passwd",
            Protocol::TCP,
            0
        },
        {
            "SIG-003",
            "Tactical Telemetry C2 Probe",
            AlertSeverity::CRITICAL,
            "BEACON_HEARTBEAT_ACK_V1",
            Protocol::UDP,
            0
        },
        {
            "SIG-004",
            "Metasploit Shellcode NOP Sled",
            AlertSeverity::HIGH,
            "\x90\x90\x90\x90\x90\x90\x90\x90",
            Protocol::TCP,
            0
        }
    };
}

std::vector<Alert> DetectionEngine::evaluate(const ParsedPacket& packet) {
    std::vector<Alert> alerts;

    auto sig_alerts = detect_signatures(packet);
    alerts.insert(alerts.end(), sig_alerts.begin(), sig_alerts.end());

    auto scan_alerts = detect_port_scan(packet);
    alerts.insert(alerts.end(), scan_alerts.begin(), scan_alerts.end());

    return alerts;
}

std::vector<Alert> DetectionEngine::detect_signatures(const ParsedPacket& packet) {
    std::vector<Alert> alerts;
    if (packet.payload.empty()) {
        return alerts;
    }

    std::string payload_str(packet.payload.begin(), packet.payload.end());

    for (const auto& sig : signatures_) {
        if (sig.protocol != Protocol::UNKNOWN && sig.protocol != packet.protocol) {
            continue;
        }
        if (sig.target_port != 0 && sig.target_port != packet.dst_port) {
            continue;
        }

        if (payload_str.find(sig.pattern) != std::string::npos) {
            alerts.push_back({
                packet.timestamp,
                sig.severity,
                sig.name,
                "Payload signature matched pattern: [" + sig.id + "]",
                packet.src_ip,
                packet.dst_ip,
                packet.src_port,
                packet.dst_port
            });
        }
    }

    return alerts;
}

std::vector<Alert> DetectionEngine::detect_port_scan(const ParsedPacket& packet) {
    std::vector<Alert> alerts;

    // Track horizontal/vertical TCP SYN probes
    if (packet.protocol != Protocol::TCP || !packet.is_syn || packet.is_ack) {
        return alerts;
    }

    auto now = std::chrono::steady_clock::now();
    auto& tracker = scan_trackers_[packet.src_ip];

    if (tracker.unique_ports.empty() || (now - tracker.window_start) > SCAN_WINDOW) {
        tracker.window_start = now;
        tracker.unique_ports.clear();
    }

    tracker.unique_ports.insert(packet.dst_port);

    if (tracker.unique_ports.size() == SCAN_THRESHOLD) {
        alerts.push_back({
            packet.timestamp,
            AlertSeverity::MEDIUM,
            "TCP SYN Port Scan Detected",
            "Source contacted " + std::to_string(SCAN_THRESHOLD) + " distinct ports within 5s window",
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port
        });
    }

    return alerts;
}

} // namespace nids