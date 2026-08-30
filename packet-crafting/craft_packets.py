#!/usr/bin/env python
"""
Packet crafting utility — the "Packet Modification and Creation" half of
Scapy fundamentals: building packets from layers (IP/TCP/UDP/DNS) with
default-or-user-specified field values, then modifying fields on an
already-built packet.

Pure construction and inspection — nothing here sends a single byte onto
any network, on purpose. That keeps every check in this file runnable
anywhere, by anyone, with no privilege requirements and no network policy
to worry about: every assertion is verified against the packet object's
own structure in memory, the same way you'd sanity-check a packet in a
Python REPL before ever deciding whether to send it.

Usage:
    python craft_packets.py --show-dns              # build + show a DNS
                                                        query packet
    python craft_packets.py --show-tcp               # build + show a TCP
                                                        SYN packet
    python craft_packets.py --modify-port 8080        # build a TCP packet
                                                        targeting port 80,
                                                        then modify its
                                                        destination port,
                                                        verifying the change
    python craft_packets.py --self-test               # runs all of the above
                                                        as assertions, not
                                                        just prints
"""
import sys

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP

sys.stdout.reconfigure(encoding="utf-8")


def build_dns_query(domain="example.com"):
    """Layers stacked with '/', exactly like the course material: an IP
    header, a UDP header (port 53), and a DNS question section — the
    request half of what dns_recon.py already sends via dnspython, built
    here from raw Scapy layers instead."""
    return IP(dst="127.0.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))


def build_tcp_syn(dst="127.0.0.1", dport=80):
    """A single SYN packet — the first half of a TCP handshake, and the
    building block lan_attack_surface.py's full-connect probing does at a
    higher level via plain sockets. This is the same thing one layer down."""
    return IP(dst=dst) / TCP(dport=dport, flags="S")


def modify_destination_port(pkt, new_port):
    """Field modification: change one attribute on an already-built
    packet and prove the change actually took, rather than just asserting
    it worked."""
    original = pkt[TCP].dport
    pkt[TCP].dport = new_port
    assert pkt[TCP].dport == new_port, "modification did not apply"
    return original, pkt[TCP].dport


def self_test():
    print("=== Packet crafting self-test (build + modify, no network I/O) ===\n")

    print("--- DNS query packet ---")
    dns_pkt = build_dns_query("example.com")
    assert dns_pkt.haslayer(DNS), "DNS layer missing"
    assert dns_pkt[DNS].qd.qname == b"example.com.", f"unexpected qname: {dns_pkt[DNS].qd.qname}"
    assert dns_pkt.haslayer(UDP) and dns_pkt[UDP].dport == 53, "not targeting UDP/53"
    print(f"  Built: {dns_pkt.summary()}")
    print(f"  Verified: DNS layer present, qname={dns_pkt[DNS].qd.qname.decode()}, UDP/53")

    print("\n--- TCP SYN packet ---")
    syn_pkt = build_tcp_syn(dport=80)
    assert syn_pkt.haslayer(TCP), "TCP layer missing"
    assert syn_pkt[TCP].flags == "S", f"unexpected flags: {syn_pkt[TCP].flags}"
    assert syn_pkt[TCP].dport == 80, "not targeting port 80"
    print(f"  Built: {syn_pkt.summary()}")
    print(f"  Verified: TCP layer present, flags=S (SYN), dport=80")

    print("\n--- Field modification ---")
    before, after = modify_destination_port(syn_pkt, 8080)
    print(f"  dport before: {before}, after: {after}")
    print(f"  Verified: modification applied and confirmed on the packet object itself")

    print("\nSelf-test PASSED — all builds and the modification verified against "
          "the packet objects themselves, not just printed and assumed correct.")


def main():
    args = sys.argv[1:]
    if "--self-test" in args:
        self_test()
        return
    if "--show-dns" in args:
        build_dns_query().show()
        return
    if "--show-tcp" in args:
        build_tcp_syn().show()
        return
    if "--modify-port" in args:
        i = args.index("--modify-port")
        new_port = int(args[i + 1])
        pkt = build_tcp_syn(dport=80)
        before, after = modify_destination_port(pkt, new_port)
        print(f"Before: dport={before}\nAfter:  dport={after}")
        pkt.show()
        return
    print("Usage: python craft_packets.py [--show-dns | --show-tcp | --modify-port N | --self-test]")


if __name__ == "__main__":
    main()
