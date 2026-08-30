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

A note on a real bug this project used to misattribute: earlier verified
output claimed live-captured frames showing as opaque "eth > data" (no ip
layer, empty DNS/HTTP/TLS sections) was "a known effect of NIC hardware
checksum/segmentation offload." That explanation was wrong. The actual
cause, found while testing against a downloaded (not live-captured) real
training pcap that showed the identical symptom: this machine's Wireshark
profile has the `ip` and `http` dissectors explicitly disabled in
%APPDATA%\\Wireshark\\disabled_protos — global state that has nothing to do
with NIC offload or how a capture was taken. Fixed by passing
--enable-protocol on every tshark invocation below, which overrides that
disabled state for just this process without touching your saved
Wireshark preferences — this script no longer depends on this machine's
ambient Wireshark configuration being in any particular state.
"""
import subprocess
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

TSHARK = r"C:\Program Files\Wireshark\tshark.exe"
WIRESHARK = r"C:\Program Files\Wireshark\Wireshark.exe"
CAPTURE_DIR = Path(__file__).parent / "captures"

# Overrides this machine's disabled_protos state for just this process -
# see the module docstring for how this was actually found and why the
# earlier "NIC offload" explanation was wrong.
FORCE_ENABLE = ["--enable-protocol", "ip", "--enable-protocol", "http"]


def run_tshark(args, pcap_path):
    result = subprocess.run([TSHARK, "-r", str(pcap_path)] + FORCE_ENABLE + args,
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
        return True
    print("  (none)")
    return False


def suspicious_indicators(pcap_path):
    print("\n=== Suspicious indicators ===")
    findings = []
    filter_terms = []

    auth = run_tshark(["-Y", "http.authorization"], pcap_path)
    if auth:
        findings.append("HIGH: cleartext HTTP Authorization header present — credentials sent unencrypted")
        filter_terms.append("http.authorization")

    cleartext = run_tshark(["-Y", "ftp || telnet"], pcap_path)
    if cleartext:
        findings.append("MEDIUM: FTP or Telnet traffic detected — cleartext legacy protocol in use")
        filter_terms.append("ftp || telnet")

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
        filter_terms.append("arp")

    if findings:
        for f in findings:
            print(f"  {f}")
    else:
        print("  None found in this capture.")
    return filter_terms


def build_display_filter(had_http, suspicious_filter_terms):
    """Derives what --open-wireshark should actually show, instead of the
    raw unfiltered capture: whatever this run's own suspicious-indicators
    pass and HTTP-request check actually found, combined into one
    display-filter expression. Validated with tshark -Y before ever being
    handed to the GUI — same filter engine, so a syntax error here would
    also mean a broken GUI launch, and this way it's caught first."""
    terms = list(suspicious_filter_terms)
    if had_http:
        terms.append("http.request")
    if not terms:
        return None
    return " || ".join(f"({t})" for t in terms)


def validate_filter(display_filter, pcap_path):
    """Runs the filter through tshark first - if it errors here, it would
    have errored identically in the GUI (same filter parser), so this
    catches a bad filter before ever launching Wireshark with one."""
    result = subprocess.run(
        [TSHARK, "-r", str(pcap_path)] + FORCE_ENABLE + ["-Y", display_filter, "-c", "1"],
        capture_output=True, text=True, timeout=15,
    )
    return result.returncode == 0


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
    had_http = http_requests(pcap_path)
    filter_terms = suspicious_indicators(pcap_path)

    if open_gui:
        display_filter = build_display_filter(had_http, filter_terms)
        if display_filter and validate_filter(display_filter, pcap_path):
            print(f"\nOpening {pcap_path} in Wireshark, filtered to what this run actually "
                  f"found: {display_filter}")
            subprocess.Popen([WIRESHARK, str(pcap_path), "-Y", display_filter])
        else:
            if display_filter:
                print(f"\n(Derived filter '{display_filter}' didn't validate — opening unfiltered instead.)")
            print(f"Opening {pcap_path} in Wireshark...")
            subprocess.Popen([WIRESHARK, str(pcap_path)])


if __name__ == "__main__":
    main()
