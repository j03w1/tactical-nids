#pragma once

#include "PacketTypes.hpp"
#include <pcap.h>
#include <optional>

namespace nids {

class PacketParser {
public:
    PacketParser() = default;
    ~PacketParser() = default;

    // Dissects raw frames, verifying bounds to prevent buffer over-reads
    std::optional<ParsedPacket> parse(const struct pcap_pkthdr* header, const uint8_t* bytes);

private:
    static std::string ip_to_string(uint32_t ip_bytes_network_order);
};

} // namespace nids