#!/usr/bin/env python3
"""
Generates synthetic traffic (.pcap) containing both benign frames
and simulated attack vectors to validate TacticalNIDS detection logic.
"""
from scapy.all import IP, TCP, UDP, Raw, wrpcap

def build_pcap():
    packets = []
    src = "192.168.10.45"
    dst = "192.168.10.1"

    print("[*] Generating baseline benign traffic...")
    for port in [80, 443, 53]:
        packets.append(IP(src=src, dst=dst)/TCP(sport=54321, dport=port, flags="S"))
        packets.append(IP(src=dst, dst=src)/TCP(sport=port, dport=54321, flags="SA"))

    print("[*] Simulating TCP SYN Port Scan (18 distinct target ports)...")
    for port in range(1000, 1018):
        packets.append(IP(src=src, dst=dst)/TCP(sport=49152, dport=port, flags="S"))

    print("[*] Simulating Command Injection Exploit Payload...")
    cmd_inj = IP(src=src, dst=dst)/TCP(sport=50001, dport=8080, flags="PA")/Raw(load="POST /api HTTP/1.1\r\n\r\n; /bin/sh -i")
    packets.append(cmd_inj)

    print("[*] Simulating Directory Traversal Payload...")
    traversal = IP(src=src, dst=dst)/TCP(sport=50002, dport=80, flags="PA")/Raw(load="GET /view?file=../../etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n")
    packets.append(traversal)

    print("[*] Simulating Tactical C2 Probe (UDP)...")
    c2 = IP(src=src, dst=dst)/UDP(sport=9999, dport=4000)/Raw(load="BEACON_HEARTBEAT_ACK_V1")
    packets.append(c2)

    wrpcap("tests/synthetic_attack.pcap", packets)
    print("[+] Wrote tests/synthetic_attack.pcap successfully.")

if __name__ == "__main__":
    build_pcap()