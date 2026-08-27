#!/usr/bin/env python
"""
Network-to-process correlation — extends MITRE Shield Collect into practical
attribution: a packet capture shows *what* traffic happened, but not *which
process* caused it. This closes that gap using psutil's per-process
connection table, the same technique a SOC analyst uses to answer "what is
actually making this connection?"

Two modes:
  --domains d1,d2   resolve domains to IPs, then find processes with an
                     active connection to any of them (e.g. domains flagged
                     by pcap_analysis.py's DNS-query output)
  --ip 1.2.3.4      find processes connected to a specific IP directly

Usage:
    python correlate_connections.py --domains api.bitcore.io,api.blockcypher.com
    python correlate_connections.py --ip 172.66.134.253
"""
import argparse
import socket
import sys

import psutil

sys.stdout.reconfigure(encoding="utf-8")


def resolve_domains(domains):
    ips = set()
    for d in domains:
        try:
            for info in socket.getaddrinfo(d, None):
                ips.add(info[4][0])
        except socket.gaierror as e:
            print(f"  Could not resolve {d}: {e}")
    return ips


def find_processes_for_ips(target_ips):
    matches = []
    for p in psutil.process_iter(["pid", "name", "username"]):
        try:
            conns = p.net_connections(kind="inet")
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        for c in conns:
            if c.raddr and c.raddr.ip in target_ips:
                matches.append((p.info["pid"], p.info["name"], p.info["username"], c.raddr.ip, c.raddr.port))
    return matches


def main():
    parser = argparse.ArgumentParser(description="Correlate network connections to the process that owns them.")
    parser.add_argument("--domains", help="Comma-separated domains to resolve and match")
    parser.add_argument("--ip", help="A single IP to match directly")
    args = parser.parse_args()

    if not args.domains and not args.ip:
        parser.error("pass --domains or --ip")

    target_ips = set()
    if args.domains:
        domains = [d.strip() for d in args.domains.split(",")]
        print(f"Resolving: {domains}")
        target_ips |= resolve_domains(domains)
    if args.ip:
        target_ips.add(args.ip)

    print(f"Target IPs: {target_ips}\n")

    matches = find_processes_for_ips(target_ips)
    if not matches:
        print("No active connections found to these IPs right now — the connection "
              "may have already closed (this only sees LIVE connections, not history).")
        return

    print("=== Matches ===")
    for pid, name, user, ip, port in matches:
        print(f"  PID {pid:>6}  {name:25}  {user}  -> {ip}:{port}")


if __name__ == "__main__":
    main()
