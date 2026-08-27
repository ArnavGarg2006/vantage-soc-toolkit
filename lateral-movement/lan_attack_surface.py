#!/usr/bin/env python
"""
Lateral movement attack-surface mapper — MITRE ATT&CK Lateral Movement
tactic (T1021 Remote Services: SSH, RDP, SMB, WinRM).

Same own-LAN-only scoping as discovery/local_discovery.py's ARP sweep: this
only ever reaches devices on your own directly-connected network segment,
never crosses the internet. For each live host found, does a plain TCP
connect probe (not a stealth/SYN scan — a completed handshake, the same
thing a browser or SSH client does) against the ports real lateral-movement
techniques actually use, and reports which are reachable. This is exactly
the "what's my actual exposure" question a real pentester or defender asks
before worrying about specific exploits.

Usage:
    python lan_attack_surface.py
"""
import ipaddress
import socket
import sys
from pathlib import Path

import psutil

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

LATERAL_MOVEMENT_PORTS = {
    22: "SSH",
    3389: "RDP",
    445: "SMB",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    135: "RPC (used by PsExec-style tools)",
}


def get_local_subnet():
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")):
                parts = a.address.split(".")
                return ".".join(parts[:3]) + ".0/24", a.address
    return None, None


def arp_sweep(subnet):
    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        print("scapy not available — cannot enumerate live hosts.")
        return []
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered, _ = srp(ether / arp, timeout=3, verbose=False)
    return [r.psrc for _, r in answered]


def probe_ports(host, timeout=0.5):
    open_ports = []
    for port, service in LATERAL_MOVEMENT_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((host, port)) == 0:
                open_ports.append((port, service))
        except OSError:
            pass
        finally:
            s.close()
    return open_ports


def main():
    subnet, my_ip = get_local_subnet()
    if not subnet:
        print("Could not determine local subnet.")
        return

    print(f"Sweeping {subnet} for live hosts (this machine: {my_ip})...")
    hosts = arp_sweep(subnet)
    print(f"Found {len(hosts)} live host(s). Probing lateral-movement ports on each...\n")

    total_exposed = 0
    for host in sorted(hosts, key=lambda ip: tuple(int(p) for p in ip.split("."))):
        open_ports = probe_ports(host)
        marker = " (this machine)" if host == my_ip else ""
        if open_ports:
            total_exposed += 1
            services = ", ".join(f"{port}/{svc}" for port, svc in open_ports)
            print(f"  {host}{marker}: OPEN -> {services}")
            emit(source="lan_attack_surface", technique_id="T1021", severity="LOW",
                 message=f"{host}{marker} exposes lateral-movement port(s): {services}")
        else:
            print(f"  {host}{marker}: none of the checked ports open")

    print(f"\n{total_exposed}/{len(hosts)} host(s) on your LAN expose at least one "
          f"common lateral-movement port.")


if __name__ == "__main__":
    main()
