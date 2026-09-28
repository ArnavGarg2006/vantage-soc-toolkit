#!/usr/bin/env python
"""
Domain age checker — MITRE ATT&CK Resource Development tactic
(T1583.001 Acquire Infrastructure: Domains), from the defensive side.

Attackers frequently register domains shortly before using them in a
campaign — a domain that's days or weeks old is a real, widely-used
suspicion signal (many SOC tools auto-flag anything under 30 days old).
This queries public WHOIS data only — the same information anyone can look
up — and flags recently-registered domains.

Usage:
    python domain_age_checker.py example.com [more.domains ...]
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

import whois

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

SUSPICIOUS_AGE_DAYS = 30


def check_domain(domain):
    print(f"=== {domain} ===")
    try:
        w = whois.whois(domain)
    except Exception as e:
        # WHOIS needs outbound network and the answer varies by registry.
        # Callers get an explicit error result rather than None so an
        # automated pipeline can tell "lookup failed" apart from
        # "looked up fine, nothing suspicious".
        print(f"  Lookup failed: {e}")
        return {"domain": domain, "error": str(e), "age_days": None, "suspicious": False}

    creation = w.creation_date
    if isinstance(creation, list):
        creation = creation[0]

    if not creation:
        print("  No creation date available from WHOIS (privacy-protected or a TLD with limited data).")
        return {"domain": domain, "error": "no creation date in WHOIS",
                "age_days": None, "suspicious": False}

    if creation.tzinfo is None:
        creation = creation.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - creation).days

    print(f"  Registered: {creation.date()} ({age_days} days ago)")
    print(f"  Registrar:  {w.registrar}")
    if age_days < SUSPICIOUS_AGE_DAYS:
        msg = f"{domain} registered {age_days}d ago (< {SUSPICIOUS_AGE_DAYS}d threshold)"
        print(f"  ⚠️  MEDIUM: registered within the last {SUSPICIOUS_AGE_DAYS} days — "
              f"a real (if imperfect) signal worth combining with other indicators, "
              f"not a verdict on its own.")
        emit(source="domain_age_checker", technique_id="T1583.001", severity="MEDIUM", message=msg)
    else:
        print(f"  Older than the {SUSPICIOUS_AGE_DAYS}-day threshold.")

    # Returned as well as printed so soar/playbook_runner.py can act on the
    # result programmatically instead of scraping stdout. Printing is
    # unchanged, so the CLI behaves exactly as before.
    return {"domain": domain, "error": None, "age_days": age_days,
            "registrar": str(w.registrar), "created": str(creation.date()),
            "suspicious": age_days < SUSPICIOUS_AGE_DAYS}


def main():
    domains = sys.argv[1:] or ["example.com"]
    for d in domains:
        check_domain(d)
        print()


if __name__ == "__main__":
    main()
