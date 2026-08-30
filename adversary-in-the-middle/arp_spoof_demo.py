#!/usr/bin/env python
"""
Adversary-in-the-Middle: ARP spoofing — MITRE ATT&CK technique (T1557.002
ARP Cache Poisoning) paired with a real ARP-spoofing detector.

Never sends anything onto the real network. Scapy is used to CRAFT a real,
correctly-formed spoofed ARP reply — the actual technique, built from the
same ARP/Ether layers the course material covers — but it's handed
directly to the detector's parser in memory, never broadcast via
sendp()/send(). Nothing here can poison a real ARP cache, on this machine
or any other; this demonstrates the mechanism and the detection, not a
usable attack tool.

The "legit" baseline isn't a placeholder: it's read straight from this
machine's real ARP cache (`arp -a`), a genuine live IP->MAC mapping seen on
the actual LAN. The demo then crafts a spoofed reply claiming that SAME IP
now belongs to a different (fake) MAC. One IP, two conflicting MACs
claimed — that conflict is the actual ARP-spoofing/cache-poisoning
signature real IDS tools (arpwatch, Suricata's ARP rules) watch for.

Usage:
    python arp_spoof_demo.py --self-test
"""
import re
import subprocess
import sys
from pathlib import Path

from scapy.layers.l2 import ARP, Ether

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

ARP_LINE = re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+dynamic", re.MULTILINE)
FAKE_ATTACKER_MAC = "de:ad:be:ef:13:37"  # obviously fake, never a real vendor prefix


def get_real_arp_entry():
    """Reads this machine's actual ARP cache and returns one real, live
    (IP, MAC) pair it has genuinely seen on the LAN — not synthetic data."""
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
    match = ARP_LINE.search(result.stdout)
    if not match:
        return None, None
    ip, mac = match.group(1), match.group(2).replace("-", ":").lower()
    return ip, mac


def craft_legit_reply(ip, mac):
    """Builds the real (non-spoofed) ARP reply for the baseline sighting —
    same layer construction as the spoofed one, just with the true MAC."""
    return Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=ip, hwsrc=mac, pdst=ip, hwdst=mac)


def craft_spoofed_reply(ip, fake_mac):
    """This is the actual technique: an ARP reply nobody asked for,
    claiming a real IP now maps to an attacker-controlled MAC. Built, never
    sent — see module docstring."""
    return Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=ip, hwsrc=fake_mac, pdst=ip, hwdst=fake_mac)


class ARPSpoofDetector:
    """Maintains a table of every (IP -> MAC) mapping it has observed. A
    NEW mapping for an IP it already has a DIFFERENT MAC on record for is
    flagged — the same cache-poisoning signature real ARP-watch tools use."""

    def __init__(self):
        self.known = {}

    def observe(self, pkt):
        if not pkt.haslayer(ARP) or pkt[ARP].op != 2:  # only ARP replies (is-at)
            return None
        ip, mac = pkt[ARP].psrc, pkt[ARP].hwsrc
        prior = self.known.get(ip)
        if prior is None:
            self.known[ip] = mac
            return None
        if prior != mac:
            return {
                "ip": ip, "prior_mac": prior, "new_mac": mac,
                "message": f"{ip} was {prior}, now claimed by {mac} — conflicting ARP reply, classic cache-poisoning signature",
            }
        return None


def self_test():
    print("=== ARP spoofing detector self-test ===\n")
    ip, real_mac = get_real_arp_entry()
    if not ip:
        print("Could not read a real dynamic entry from this machine's ARP cache "
              "(arp -a) — nothing to build the demo on. Try again after some real "
              "LAN traffic (e.g. run discovery/local_discovery.py --scan-lan first).")
        return

    print(f"Real baseline from this machine's own ARP cache: {ip} -> {real_mac}")
    detector = ARPSpoofDetector()

    legit = craft_legit_reply(ip, real_mac)
    result = detector.observe(legit)
    print(f"Observed legit reply for {ip} -> {real_mac}: {'no alert (expected — first sighting)' if result is None else 'unexpected alert!'}")

    print(f"\nCrafting a SPOOFED ARP reply: {ip} -> {FAKE_ATTACKER_MAC} (never sent — built and analyzed in memory only)")
    spoofed = craft_spoofed_reply(ip, FAKE_ATTACKER_MAC)
    result = detector.observe(spoofed)

    if result:
        print(f"  ⚠️  HIGH: {result['message']}")
        emit(source="arp_spoof_demo", technique_id="T1557.002", severity="HIGH", message=result["message"])
    print(f"\n{'Self-test PASSED' if result else 'Self-test FAILED'} — "
          f"{'conflicting mapping correctly flagged.' if result else 'spoofed reply was not caught.'}")


def main():
    if "--self-test" in sys.argv:
        self_test()
    else:
        print("Usage: python arp_spoof_demo.py --self-test")


if __name__ == "__main__":
    main()
