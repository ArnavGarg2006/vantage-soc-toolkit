#!/usr/bin/env python
"""
Packet capture & summarization — MITRE Shield Collect tactic (DTE0002 Network Monitoring)

Captures live traffic on this machine for a short, bounded window, writes a
.pcap for later analysis, and prints a protocol/talker summary. This is
purely passive — it observes traffic already flowing to/from this machine,
it does not send anything.

Usage:
    python packet_capture.py [seconds] [interface]
"""
import sys
import time
from collections import Counter
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

CAPTURE_DIR = Path(__file__).parent / "captures"


def main():
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    iface = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, wrpcap
    except ImportError:
        print("scapy is not installed. pip install scapy")
        return

    CAPTURE_DIR.mkdir(exist_ok=True)
    out_path = CAPTURE_DIR / f"capture_{int(time.time())}.pcap"

    print(f"Capturing for {duration}s on {iface or 'default interface'}... "
          f"(needs administrator/elevated terminal for raw capture on Windows)")
    try:
        packets = sniff(timeout=duration, iface=iface)
    except PermissionError:
        print("Requires administrator privileges — run this script from an elevated terminal.")
        return
    except Exception as e:
        print(f"Capture failed: {type(e).__name__}: {e}")
        return

    if not packets:
        print("No packets captured (idle interface, or wrong interface selected).")
        return

    wrpcap(str(out_path), packets)
    print(f"\nCaptured {len(packets)} packets -> {out_path}")

    protocol_counts = Counter()
    talkers = Counter()
    for pkt in packets:
        if pkt.haslayer(TCP):
            protocol_counts["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocol_counts["UDP"] += 1
        elif pkt.haslayer(ICMP):
            protocol_counts["ICMP"] += 1
        elif pkt.haslayer(ARP):
            protocol_counts["ARP"] += 1
        else:
            protocol_counts["other"] += 1

        if pkt.haslayer(IP):
            talkers[pkt[IP].src] += 1

    print("\n=== Protocol breakdown ===")
    for proto, count in protocol_counts.most_common():
        print(f"  {proto:6}  {count}")

    print("\n=== Top talkers (source IP) ===")
    for ip, count in talkers.most_common(5):
        print(f"  {ip:15}  {count} packets")


if __name__ == "__main__":
    main()
