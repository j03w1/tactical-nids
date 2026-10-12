#include "PacketParser.hpp"
#include "DetectionEngine.hpp"
#include "AlertLogger.hpp"
#include <iostream>
#include <csignal>
#include <atomic>
#include <pcap.h>

std::atomic<bool> g_running{true};

void handle_signal(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        g_running.store(false);
    }
}

void print_usage(const char* prog_name) {
    std::cerr << "Usage:\n"
              << "  Live Capture:   sudo " << prog_name << " -i <interface>\n"
              << "  PCAP Analysis:  " << prog_name << " -r <file.pcap>\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    std::string mode = argv[1];
    std::string target = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = nullptr;

    if (mode == "-r") {
        handle = pcap_open_offline(target.c_str(), errbuf);
        if (!handle) {
            std::cerr << "[-] Error opening pcap file: " << errbuf << "\n";
            return 1;
        }
        std::cout << "[+] Processing PCAP artifact: " << target << "\n";
    } else if (mode == "-i") {
        handle = pcap_create(target.c_str(), errbuf);
        if (!handle) {
            std::cerr << "[-] Error creating live handle: " << errbuf << "\n";
            return 1;
        }
        pcap_set_snaplen(handle, 65535);
        pcap_set_promisc(handle, 1);
        pcap_set_timeout(handle, 100); // 100 ms read timeout
        if (pcap_activate(handle) != 0) {
            std::cerr << "[-] Failed to activate live interface: " << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            return 1;
        }
        std::cout << "[+] Listening on interface: " << target << "\n";
    } else {
        print_usage(argv[0]);
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    nids::PacketParser parser;
    nids::DetectionEngine engine;
    nids::AlertLogger logger;

    uint64_t total_packets = 0;
    uint64_t total_alerts = 0;

    struct pcap_pkthdr* header = nullptr;
    const uint8_t* data = nullptr;

    while (g_running.load()) {
        int res = pcap_next_ex(handle, &header, &data);
        if (res == 1) { // Packet read successfully
            total_packets++;
            auto parsed = parser.parse(header, data);
            if (parsed.has_value()) {
                auto alerts = engine.evaluate(parsed.value());
                for (const auto& alert : alerts) {
                    logger.log(alert);
                    total_alerts++;
                }
            }
        } else if (res == 0) {
            // Buffer timeout, continue loop
            continue;
        } else if (res == -1) {
            std::cerr << "[-] Capture read error: " << pcap_geterr(handle) << "\n";
            break;
        } else if (res == -2) {
            // End of offline PCAP file reached
            break;
        }
    }

    std::cout << "\n[+] Session Concluded.\n"
              << "    Total Packets Processed: " << total_packets << "\n"
              << "    Threat Alerts Raised:    " << total_alerts << "\n";

    pcap_close(handle);
    return 0;
}