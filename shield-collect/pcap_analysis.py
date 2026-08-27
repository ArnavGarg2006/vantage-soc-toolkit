#!/usr/bin/env python
"""
tshark-powered deep packet capture analysis — MITRE Shield Collect (DTE0002)
extending into Detect (DTE0007) via the suspicious-indicators pass.

packet_capture.py (scapy) captures traffic and gives a basic protocol/talker
count. This script hands that same .pcap to tshark — Wireshark's CLI engine —
for the analysis scapy can't easily do on its own: full protocol hierarchy,
conversation statistics, DNS query extraction, TLS SNI extraction (which
domains were contacted, readable even though the traffic itself is
encrypted), cleartext HTTP host/URI extraction, and a pass for genuinely
suspicious findings (cleartext credentials, cleartext legacy protocols).

Usage:
    python pcap_analysis.py [path/to/file.pcap]     # defaults to the most
                                                       # recent capture
    python pcap_analysis.py --open-wireshark [file]  # also launch the GUI
"""
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
WIRESHARK = r"C:\Program Files\Wireshark\Wireshark.exe"
CAPTURE_DIR = Path(__file__).parent / "captures"


def run_tshark(args, pcap_path):
    result = subprocess.run([TSHARK, "-r", str(pcap_path)] + args,
                             capture_output=True, text=True, timeout=30)
    return result.stdout.strip()


def most_recent_capture():
    caps = sorted(CAPTURE_DIR.glob("*.pcap"), key=lambda p: p.stat().st_mtime)
    return caps[-1] if caps else None


def protocol_hierarchy(pcap_path):
    print("=== Protocol hierarchy (tshark -z io,phs) ===")
    out = run_tshark(["-q", "-z", "io,phs"], pcap_path)
    print(out or "  (no output)")


def top_conversations(pcap_path):
    print("\n=== IP conversations (tshark -z conv,ip) ===")
    out = run_tshark(["-q", "-z", "conv,ip"], pcap_path)
    print(out or "  (no output)")


def dns_queries(pcap_path):
    print("\n=== DNS queries observed ===")
    out = run_tshark(["-Y", "dns.flags.response == 0", "-T", "fields", "-e", "dns.qry.name"], pcap_path)
    names = sorted(set(n for n in out.splitlines() if n))
    if names:
        for n in names:
            print(f"  {n}")
    else:
        print("  (none)")


def tls_sni(pcap_path):
    print("\n=== TLS SNI (destinations visible even in encrypted traffic) ===")
    out = run_tshark(["-Y", "tls.handshake.extensions_server_name",
                       "-T", "fields", "-e", "tls.handshake.extensions_server_name"], pcap_path)
    names = sorted(set(n for n in out.splitlines() if n))
    if names:
        for n in names:
            print(f"  {n}")
    else:
        print("  (none — no TLS handshakes captured)")


def http_requests(pcap_path):
    print("\n=== Cleartext HTTP requests ===")
    out = run_tshark(["-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.request.uri"], pcap_path)
    if out:
        for line in out.splitlines():
            print(f"  {line}")
    else:
        print("  (none)")


def suspicious_indicators(pcap_path):
    print("\n=== Suspicious indicators ===")
    findings = []

    auth = run_tshark(["-Y", "http.authorization"], pcap_path)
    if auth:
        findings.append("HIGH: cleartext HTTP Authorization header present — credentials sent unencrypted")

    cleartext = run_tshark(["-Y", "ftp || telnet"], pcap_path)
    if cleartext:
        findings.append("MEDIUM: FTP or Telnet traffic detected — cleartext legacy protocol in use")

    arp_replies = run_tshark(["-Y", "arp.opcode == 2", "-T", "fields", "-e", "arp.src.hwaddr", "-e", "arp.src.proto_ipv4"], pcap_path)
    ip_to_macs = {}
    for line in arp_replies.splitlines():
        parts = line.split("\t")
        if len(parts) == 2:
            mac, ip = parts
            ip_to_macs.setdefault(ip, set()).add(mac)
    conflicting = {ip: macs for ip, macs in ip_to_macs.items() if len(macs) > 1}
    if conflicting:
        findings.append(f"HIGH: possible ARP spoofing — {len(conflicting)} IP(s) claimed by multiple MAC addresses: {conflicting}")

    if findings:
        for f in findings:
            print(f"  {f}")
    else:
        print("  None found in this capture.")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    open_gui = "--open-wireshark" in sys.argv

    pcap_path = Path(args[0]) if args else most_recent_capture()
    if not pcap_path or not pcap_path.exists():
        print("No .pcap file found. Run packet_capture.py first, or pass a path.")
        return

    print(f"Analyzing: {pcap_path}\n")
    protocol_hierarchy(pcap_path)
    top_conversations(pcap_path)
    dns_queries(pcap_path)
    tls_sni(pcap_path)
    http_requests(pcap_path)
    suspicious_indicators(pcap_path)

    if open_gui:
        print(f"\nOpening {pcap_path} in Wireshark...")
        subprocess.Popen([WIRESHARK, str(pcap_path)])


if __name__ == "__main__":
    main()
