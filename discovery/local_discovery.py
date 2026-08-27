#!/usr/bin/env python
"""
Local & network discovery — MITRE ATT&CK Discovery tactic
  T1082 System Information Discovery
  T1057 Process Discovery
  T1016 System Network Configuration Discovery
  T1018 Remote System Discovery (own-LAN ARP sweep only)

Everything here reads local system state or sweeps the machine's OWN local
subnet — the same category of activity as opening Task Manager or your
router's device list. The ARP sweep only reaches devices on your own
directly-connected network segment; it cannot cross the internet.

Usage:
    python local_discovery.py [--scan-lan]
"""
import sys
import socket
import platform
import argparse

import psutil

sys.stdout.reconfigure(encoding="utf-8")


def system_info():
    print("=== System information (T1082) ===")
    print(f"  Hostname:      {socket.gethostname()}")
    print(f"  OS:            {platform.system()} {platform.release()} ({platform.version()})")
    print(f"  Architecture:  {platform.machine()}")
    print(f"  CPU cores:     {psutil.cpu_count(logical=True)} logical / {psutil.cpu_count(logical=False)} physical")
    mem = psutil.virtual_memory()
    print(f"  Memory:        {mem.used / 1e9:.1f} GB used / {mem.total / 1e9:.1f} GB total ({mem.percent}%)")
    print(f"  Boot time:     {psutil.boot_time()}")


def process_discovery(top_n=10):
    print(f"\n=== Process discovery (T1057) — top {top_n} by memory ===")
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "memory_info"]):
        try:
            info = p.info
            mem = info["memory_info"].rss if info["memory_info"] else 0
            procs.append((info["pid"], info["name"], info["username"], mem))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: x[3], reverse=True)
    for pid, name, user, mem in procs[:top_n]:
        print(f"  PID {pid:>6}  {mem / 1e6:>7.1f} MB  {name!r:30}  {user}")
    print(f"  ({len(procs)} total processes visible)")


def network_config():
    print("\n=== Network configuration (T1016) ===")
    for iface, addrs in psutil.net_if_addrs().items():
        ipv4 = [a.address for a in addrs if a.family == socket.AF_INET]
        if ipv4:
            print(f"  {iface}: {ipv4}")


def get_local_subnet():
    """Best-effort: find this machine's own IPv4 /24 to scan. Skips loopback
    and 169.254.x.x link-local addresses (APIPA — an adapter with no active
    DHCP lease, not a real network to scan)."""
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")):
                parts = a.address.split(".")
                return ".".join(parts[:3]) + ".0/24", a.address
    return None, None


def scan_own_lan():
    print("\n=== Own-LAN discovery (T1018) — ARP sweep ===")
    subnet, my_ip = get_local_subnet()
    if not subnet:
        print("  Could not determine local subnet.")
        return
    print(f"  Scanning {subnet} (this machine: {my_ip}) — your own directly-connected network only")

    try:
        from scapy.all import ARP, Ether, srp
    except ImportError:
        print("  scapy not available.")
        return

    try:
        arp = ARP(pdst=subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        answered, _ = srp(ether / arp, timeout=3, verbose=False)
        if not answered:
            print("  No hosts responded (or admin privileges are required for raw ARP on this OS).")
        for _, received in answered:
            print(f"  {received.psrc:15}  {received.hwsrc}")
    except PermissionError:
        print("  Requires administrator privileges for raw packet send — run this script elevated.")
    except Exception as e:
        print(f"  Scan failed: {type(e).__name__}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Local system and own-LAN discovery.")
    parser.add_argument("--scan-lan", action="store_true", help="Also ARP-sweep your own local subnet")
    args = parser.parse_args()

    system_info()
    process_discovery()
    network_config()
    if args.scan_lan:
        scan_own_lan()
    else:
        print("\n(pass --scan-lan to also sweep your own local network for live hosts)")


if __name__ == "__main__":
    main()
