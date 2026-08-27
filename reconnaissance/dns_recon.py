#!/usr/bin/env python
"""
DNS reconnaissance — MITRE ATT&CK Reconnaissance tactic
  T1590.002 Gather Victim Network Information: DNS
  T1596.001 Search Open Technical Databases: DNS/Passive DNS

Passive, read-only DNS queries only — no packets sent to the target beyond
standard DNS resolution (the same requests any browser makes). Defaults to
example.com, which IANA reserves specifically for documentation and testing
(RFC 2606) — there is no real organization behind it to affect.

Usage:
    python dns_recon.py [domain]
"""
import sys
import dns.resolver
import dns.zone
import dns.query

# Windows consoles default to a legacy codepage (cp1252) that can't encode
# characters like checkmarks/warning signs — force UTF-8 stdout so this runs
# the same everywhere, without depending on the caller having run `chcp 65001`.
sys.stdout.reconfigure(encoding="utf-8")


COMMON_SUBDOMAINS = ["www", "mail", "ftp", "admin", "test", "dev", "api", "blog", "vpn", "portal"]
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]


def lookup_records(domain):
    print(f"\n=== DNS records for {domain} ===")
    results = {}
    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            values = [str(r) for r in answers]
            results[rtype] = values
            print(f"  {rtype:5} -> {values}")
        except dns.resolver.NoAnswer:
            print(f"  {rtype:5} -> (no records)")
        except dns.resolver.NXDOMAIN:
            print(f"  Domain does not exist: {domain}")
            return results
        except Exception as e:
            print(f"  {rtype:5} -> error: {e}")
    return results


def attempt_zone_transfer(domain, nameservers):
    """AXFR zone transfer — should ALWAYS fail against a properly configured
    nameserver. This is the defensive point: if this ever succeeds against a
    real target, that's a serious misconfiguration leaking the entire zone."""
    print(f"\n=== Zone transfer attempt (should fail) ===")
    if not nameservers:
        print("  No nameservers found to test.")
        return
    ns_host = nameservers[0].rstrip(".")
    try:
        ns_ip = str(dns.resolver.resolve(ns_host, "A")[0])
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
        print(f"  ⚠️  Zone transfer SUCCEEDED against {ns_host} — this is a real misconfiguration.")
        for name, node in zone.nodes.items():
            print(f"    {name}")
    except Exception as e:
        print(f"  Blocked/failed as expected: {type(e).__name__}: {e}")


def enumerate_subdomains(domain):
    print(f"\n=== Subdomain enumeration ({len(COMMON_SUBDOMAINS)} candidates) ===")
    found = []
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]
            found.append((fqdn, ips))
            print(f"  ✓ {fqdn} -> {ips}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass
        except Exception as e:
            print(f"  {fqdn} -> error: {e}")
    if not found:
        print("  No subdomains resolved from the candidate list.")
    return found


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(f"DNS reconnaissance against: {domain}")
    print("(defaults to example.com — IANA's reserved test domain, RFC 2606 — "
          "pass a domain you own/are authorized to test otherwise)")

    records = lookup_records(domain)
    attempt_zone_transfer(domain, records.get("NS", []))
    enumerate_subdomains(domain)


if __name__ == "__main__":
    main()
