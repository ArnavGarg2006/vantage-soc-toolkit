#!/usr/bin/env python
"""
Pure-Python pcap analysis via Scapy — MITRE Shield Collect (DTE0002),
complementing (not replacing) pcap_analysis.py's tshark-powered version.

pcap_analysis.py needs Wireshark/tshark installed on the machine running
it. This doesn't — rdpcap() and Scapy's own layer model do the protocol
summary, top-talkers, and layer drill-down entirely in Python, no external
binary required. The tradeoff is real and worth stating plainly: tshark's
protocol dissectors are far deeper (TLS SNI extraction, full protocol
hierarchy, DNS query parsing) — this is the lighter-weight,
zero-external-dependency alternative for when tshark isn't available.

Directly demonstrates the two things a Scapy fundamentals course teaches
for packet analysis: rdpcap() to load and summarize a capture by protocol,
and .show()-style layer drill-down to see header fields and payload data
on an individual packet.

Usage:
    python scapy_pcap_analysis.py                 # analyzes the most
                                                     # recent capture in
                                                     # shield-collect/captures/
    python scapy_pcap_analysis.py [file.pcap]       # analyze a specific file
    python scapy_pcap_analysis.py --show N [file]   # full layer drill-down
                                                       # (like packet.show())
                                                       # for packet index N
"""
import sys
from collections import Counter
from pathlib import Path

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP

sys.stdout.reconfigure(encoding="utf-8")

CAPTURE_DIR = Path(__file__).parent / "captures"

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ")
SUSPICIOUS_PORTS = {21: "FTP (cleartext)", 23: "Telnet (cleartext)", 80: "HTTP (cleartext)"}


def most_recent_capture():
    caps = sorted(CAPTURE_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
    return caps[-1] if caps else None


def protocol_summary(packets):
    """The rdpcap()-and-summarize half of the course material: what's in
    this capture, broken down by protocol."""
    print(f"=== Protocol summary ({len(packets)} packet(s)) ===")
    counts = Counter()
    for pkt in packets:
        if pkt.haslayer(ARP):
            counts["ARP"] += 1
        elif pkt.haslayer(TCP):
            counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            counts["UDP"] += 1
        elif pkt.haslayer(IP):
            counts["IP (other)"] += 1
        else:
            counts[pkt.lastlayer().name] += 1
    for proto, count in counts.most_common():
        print(f"  {proto:12} {count}")
    return counts


def top_talkers(packets, n=5):
    print(f"\n=== Top {n} talker(s) by packet count ===")
    pairs = Counter()
    for pkt in packets:
        if pkt.haslayer(IP):
            pairs[(pkt[IP].src, pkt[IP].dst)] += 1
    for (src, dst), count in pairs.most_common(n):
        print(f"  {src:16} -> {dst:16}  {count} packet(s)")


def suspicious_indicators(packets):
    """Same spirit as pcap_analysis.py's suspicious-indicators pass, done
    with Scapy's own layer access instead of tshark's dissectors: cleartext
    HTTP request lines found in a TCP payload, and traffic on legacy
    cleartext-protocol ports.

    Port-80 traffic is summarized per-port rather than flagged one line per
    packet — verified against a real 22,000-packet training capture and the
    first version flagged 3,946 individual "traffic to port 80" lines
    against only 176 genuine HTTP request lines, a 22:1 noise ratio that
    buried the actual signal. Every port-80 data/ACK packet on an
    already-flagged connection doesn't need its own line; the request-line
    extraction below already IS the real per-request signal. Ports 21/23
    stay flagged per-occurrence since they're rare enough in real traffic
    that every sighting is still worth seeing individually."""
    print("\n=== Suspicious indicators ===")
    findings = []
    port_counts = Counter()

    for i, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer("Raw"):
            payload = bytes(pkt["Raw"].load)
            if payload.startswith(HTTP_METHODS):
                line = payload.split(b"\r\n", 1)[0].decode(errors="replace")
                findings.append((i, f"Cleartext HTTP request: {line}"))
        if pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            if dport == 80:
                port_counts[80] += 1
            elif dport in SUSPICIOUS_PORTS:
                findings.append((i, f"Traffic to port {dport} ({SUSPICIOUS_PORTS[dport]})"))

    if not findings and not port_counts:
        print("  None found.")
    else:
        for idx, msg in findings:
            print(f"  ⚠️  [packet {idx}] {msg}")
        if port_counts[80]:
            print(f"  ({port_counts[80]} packet(s) on port 80 (HTTP, cleartext) — "
                  f"see the request lines above for the actual requests made)")
    return findings


def show_packet(packets, index):
    if index < 0 or index >= len(packets):
        print(f"Packet index {index} out of range (0..{len(packets) - 1}).")
        return
    print(f"=== Layer drill-down: packet {index} ===\n")
    packets[index].show()


def analyze(path):
    print(f"Loading {path} with Scapy's rdpcap()...\n")
    packets = rdpcap(str(path))
    protocol_summary(packets)
    top_talkers(packets)
    suspicious_indicators(packets)
    return packets


def main():
    args = [a for a in sys.argv[1:]]
    show_index = None
    if "--show" in args:
        i = args.index("--show")
        show_index = int(args[i + 1])
        del args[i:i + 2]

    path = Path(args[0]) if args else most_recent_capture()
    if not path or not path.exists():
        print("No capture file found. Run packet_capture.py first, or pass a .pcap path.")
        return

    packets = analyze(path)
    if show_index is not None:
        print()
        show_packet(packets, show_index)


if __name__ == "__main__":
    main()
