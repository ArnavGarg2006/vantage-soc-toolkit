#!/usr/bin/env python
"""
Certificate transparency search — MITRE ATT&CK Reconnaissance tactic
(T1596.003 Search Open Websites/Domains: Digital Certificates). Every
publicly-trusted TLS certificate issued anywhere is now permanently logged
in certificate transparency logs (a browser requirement, not optional),
and crt.sh makes those logs searchably public. That means every subdomain
a domain has EVER gotten a certificate for is discoverable here — a real,
passive OSINT technique dns_recon.py's brute-force enumeration can't
match, since it only finds subdomains it happens to guess.

crt.sh is a free, community-run service and genuinely goes down — this
was verified live at build time and hit a full outage (502 on every
endpoint, including the homepage, independent of query parameters or
user-agent). That's documented honestly below, not papered over: this
script handles the failure explicitly rather than crashing, and the
README notes the live outage rather than claiming a success that didn't
happen.

Usage:
    python cert_transparency.py example.com
"""
import sys

import requests

sys.stdout.reconfigure(encoding="utf-8")

CRT_SH_URL = "https://crt.sh/"


def search(domain):
    print(f"=== Certificate transparency search: {domain} ===\n")
    try:
        resp = requests.get(CRT_SH_URL, params={"q": domain, "output": "json"}, timeout=15)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"  crt.sh request failed: {e}")
        print("  crt.sh is a free community service and does go down — a real failure "
              "mode of relying on public infrastructure, not a bug in this script.")
        return

    try:
        certs = resp.json()
    except ValueError:
        print(f"  crt.sh returned a non-JSON response (HTTP {resp.status_code}) — "
              f"likely an outage on their end, not malformed input here.")
        return

    subdomains = set()
    for cert in certs:
        for name in cert.get("name_value", "").split("\n"):
            name = name.strip().lower()
            if name.endswith(domain.lower()):
                subdomains.add(name)

    print(f"  {len(certs)} certificate(s) found, {len(subdomains)} unique hostname(s):")
    for name in sorted(subdomains):
        print(f"    {name}")


def main():
    domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    search(domain)


if __name__ == "__main__":
    main()
