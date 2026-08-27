#!/usr/bin/env python
"""
Phishing URL analyzer — MITRE ATT&CK Initial Access tactic (T1566 Phishing),
from the purely defensive side. This never sends anything to anyone — it
only analyzes a URL string you give it for the structural characteristics
real phishing links share. No emails are composed, no messages are sent;
building an actual phishing sender is out of scope for this project, full
stop.

Checks:
  - Lookalike/typosquatted domain (edit-distance against known brands)
  - Suspicious/commonly-abused free TLDs
  - URL shortener (hides the real destination)
  - Raw IP address instead of a domain name
  - Excessive subdomain nesting or hyphens (common obfuscation)
  - '@' in the URL (everything before it is ignored by browsers - a classic
    trick to make a URL look like it points at a trusted domain)

Usage:
    python phishing_url_analyzer.py <url> [more urls...]
"""
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

KNOWN_BRANDS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "paypal.com",
    "facebook.com", "instagram.com", "netflix.com", "chase.com", "wellsfargo.com",
]
SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".work"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}


def edit_distance(a, b):
    if len(a) < len(b):
        return edit_distance(b, a)
    if len(b) == 0:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (ca != cb)))
        prev = curr
    return prev[-1]


def analyze(url):
    print(f"=== {url} ===")
    findings = []

    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if "@" in url.split("://", 1)[-1].split("/")[0]:
        findings.append(("HIGH", "'@' before the host — browsers ignore everything before it; "
                                  "the visible-looking domain may not be where this actually goes"))

    try:
        import ipaddress
        ipaddress.ip_address(host)
        findings.append(("HIGH", f"host is a raw IP address ({host}), not a domain name"))
    except ValueError:
        pass

    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            findings.append(("MEDIUM", f"uses '{tld}', a free TLD commonly abused for throwaway phishing infrastructure"))
            break

    if host in URL_SHORTENERS:
        findings.append(("MEDIUM", f"'{host}' is a URL shortener — the real destination is hidden"))

    if host.count(".") >= 4:
        findings.append(("LOW", f"unusually deep subdomain nesting ({host})"))
    if host.count("-") >= 3:
        findings.append(("LOW", f"unusually many hyphens in the hostname ({host})"))

    # Strip a leading "www." before comparing to brands, or "www.paypa1.com"
    # never gets close enough to "paypal.com" to trip the threshold - the
    # subdomain prefix alone adds more edit distance than the typosquat itself.
    compare_host = host[4:] if host.startswith("www.") else host

    best_match, best_dist = None, 99
    for brand in KNOWN_BRANDS:
        d = edit_distance(compare_host, brand)
        if d < best_dist:
            best_match, best_dist = brand, d
    if 0 < best_dist <= 2 and compare_host != best_match:
        findings.append(("HIGH", f"'{host}' is very close to '{best_match}' (edit distance {best_dist}) — "
                                  f"likely typosquatting"))

    if not findings:
        print("  No red flags from this analysis (not a guarantee of legitimacy — just no structural red flags).")
    for severity, reason in findings:
        print(f"  [{severity}] {reason}")
        emit(source="phishing_url_analyzer", technique_id="T1566", severity=severity, message=f"{url}: {reason}")


def main():
    urls = sys.argv[1:] or ["https://www.paypa1.com/login", "http://192.168.1.1/update", "https://bit.ly/3xample"]
    for url in urls:
        analyze(url)
        print()


if __name__ == "__main__":
    main()
