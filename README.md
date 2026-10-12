# TacticalNIDS: Defensive Network Intrusion Detection Engine

A lightweight, multi-threaded C++17 intrusion detection system engineered for tactical edge environments. `TacticalNIDS` parses link-layer and network-layer protocols directly using raw `libpcap` handles, evaluates packet streams against signature and behavioral heuristic engines, and emits structured JSON alerts.

## Key Capabilities

- **Zero-Copy Dissection:** Bounds-checked frame parsing supporting IPv4, TCP, UDP, and ICMP protocols.
- **Dual-Mode Detection:**
  - **Signature Matching:** Fast substring search across L7 application payloads (command injection, directory traversal, reverse shells).
  - **Behavioral Heuristics:** Sliding-window TCP SYN port-scan detection tracking source entity metrics over discrete time intervals.
- **Structured Telemetry:** Emits thread-safe, SIEM-ingestible JSON events to standard out.
- **Dual Capture Modes:** Ingests live promiscuous traffic directly from Linux network interfaces or analyzes pre-recorded `.pcap` capture files.

## Technical Architecture

```text
[ Network Interface / PCAP File ]
               │
               ▼
       [ PacketParser ]
        (Validates bounds, decodes Ethernet -> IPv4 -> TCP/UDP/ICMP)
               │
               ▼
      [ DetectionEngine ]
        ├── Signature Engine (Payload pattern inspection)
        └── Behavioral Tracker (Sliding time-window SYN metrics)
               │
               ▼
        [ AlertLogger ]  ──>  stdout (JSON Stream)