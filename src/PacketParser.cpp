#include "PacketParser.hpp"
#include <arpa/inet.h>
#include <cstring>

namespace nids {

namespace {
    constexpr size_t ETHERNET_HEADER_LEN = 14;
    constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
}

std::string PacketParser::ip_to_string(uint32_t ip_bytes_network_order) {
    char buffer[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = ip_bytes_network_order;
    if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer))) {
        return std::string(buffer);
    }
    return "0.0.0.0";
}

std::optional<ParsedPacket> PacketParser::parse(const struct pcap_pkthdr* header, const uint8_t* bytes) {
    if (!header || !bytes || header->caplen < ETHERNET_HEADER_LEN) {
        return std::nullopt;
    }

    ParsedPacket pkt;
    pkt.wire_length = header->len;
    pkt.timestamp = std::chrono::system_clock::now();

    // Verify Ethernet Frame (IPv4 only)
    uint16_t ethertype = (static_cast<uint16_t>(bytes[12]) << 8) | bytes[13];
    if (ethertype != ETHERTYPE_IPV4) {
        return std::nullopt;
    }

    size_t offset = ETHERNET_HEADER_LEN;
    if (header->caplen < offset + 20) { // Minimum IPv4 header length
        return std::nullopt;
    }

    // IPv4 Header Inspection
    uint8_t ver_ihl = bytes[offset];
    uint8_t ihl = (ver_ihl & 0x0F) * 4;
    if (ihl < 20 || header->caplen < offset + ihl) {
        return std::nullopt;
    }

    uint8_t proto_byte = bytes[offset + 9];
    uint32_t src_ip_raw = 0;
    uint32_t dst_ip_raw = 0;
    std::memcpy(&src_ip_raw, &bytes[offset + 12], 4);
    std::memcpy(&dst_ip_raw, &bytes[offset + 16], 4);

    pkt.src_ip = ip_to_string(src_ip_raw);
    pkt.dst_ip = ip_to_string(dst_ip_raw);

    offset += ihl;

    // Transport Layer Parsing
    if (proto_byte == 6) { // TCP
        pkt.protocol = Protocol::TCP;
        if (header->caplen < offset + 20) {
            return std::nullopt;
        }

        pkt.src_port = (static_cast<uint16_t>(bytes[offset]) << 8) | bytes[offset + 1];
        pkt.dst_port = (static_cast<uint16_t>(bytes[offset + 2]) << 8) | bytes[offset + 3];

        uint8_t data_offset = ((bytes[offset + 12] >> 4) & 0x0F) * 4;
        if (data_offset < 20 || header->caplen < offset + data_offset) {
            return std::nullopt;
        }

        uint8_t flags = bytes[offset + 13];
        pkt.tcp_flags = flags;
        pkt.is_fin = (flags & 0x01) != 0;
        pkt.is_syn = (flags & 0x02) != 0;
        pkt.is_rst = (flags & 0x04) != 0;
        pkt.is_ack = (flags & 0x10) != 0;

        offset += data_offset;
    } else if (proto_byte == 17) { // UDP
        pkt.protocol = Protocol::UDP;
        if (header->caplen < offset + 8) {
            return std::nullopt;
        }

        pkt.src_port = (static_cast<uint16_t>(bytes[offset]) << 8) | bytes[offset + 1];
        pkt.dst_port = (static_cast<uint16_t>(bytes[offset + 2]) << 8) | bytes[offset + 3];
        offset += 8;
    } else if (proto_byte == 1) { // ICMP
        pkt.protocol = Protocol::ICMP;
        if (header->caplen < offset + 8) {
            return std::nullopt;
        }
        offset += 8;
    } else {
        pkt.protocol = Protocol::UNKNOWN;
        return std::nullopt;
    }

    // Extract Application Payload
    if (header->caplen > offset) {
        size_t payload_len = header->caplen - offset;
        pkt.payload.assign(bytes + offset, bytes + offset + payload_len);
    }

    return pkt;
}

} // namespace nids