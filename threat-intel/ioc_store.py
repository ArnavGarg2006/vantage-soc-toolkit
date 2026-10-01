#!/usr/bin/env python
"""
Threat-intel / IOC store — the TIP-shaped gap, closed as honestly as it can
be from here.

WHAT THIS IS, AND WHAT IT DELIBERATELY IS NOT
---------------------------------------------
It is NOT a MISP or OpenCTI integration. Those are server platforms; there
is no instance behind this repo, and an API client written against a service
that is not running anywhere produces exactly what this project has refused
to ship since the first commit — code whose output nobody could verify.

What it IS: a local indicator store that speaks **MISP's published event
format**. That format is an open spec, so parsing it is a real capability
that can be proven offline against a real-shaped document. Point
`--import-misp` at any MISP JSON export, a feed file, or a URL serving one,
and the indicators land in the same SQLite store as events and cases — where
they can be joined to an alert in one query.

The distinction matters: "we speak the format, point it at a feed" is true
and checkable. "We integrate with MISP" would not be.

THE EVIDENCE TIER, STATED UP FRONT
-----------------------------------
Everything here is verified offline except one thing, and the exception is
named rather than buried:

  verified   MISP-format parsing, IOC storage, matching against event text,
             feed ingestion over real HTTP (against a localhost server
             serving a real-format document), and the whole SOAR path
  NOT        reachability of any public feed, and VirusTotal. Outbound
             network is blocked in the environment this was built in, and
             VirusTotal additionally needs an API key. The VT code path is
             exercised against a local server that mimics VT's response
             shape, which proves the parsing and the error handling — it
             does not prove anything about the live service.

If you have egress and a key, the same commands work against the real thing.
That is a claim about your environment, not about this code, and it is not
counted as verified here.

Usage:
    python threat-intel/ioc_store.py --self-test
    python threat-intel/ioc_store.py --import-misp feed.json
    python threat-intel/ioc_store.py --import-misp https://example.org/misp.json
    python threat-intel/ioc_store.py --import-list bad_ips.txt --type ip
    python threat-intel/ioc_store.py --lookup 198.51.100.7
    python threat-intel/ioc_store.py --match "beacon to 198.51.100.7 every 1.5s"
    python threat-intel/ioc_store.py --stats
    python threat-intel/ioc_store.py --vt <hash|domain|ip>     # needs VANTAGE_VT_API_KEY
"""
import argparse
import json
import os
import re
import sqlite3
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

DB_PATH = PROJECT_ROOT / "event-bus" / "events.db"
SELF_TEST_MARKER = "ioc_self_test"

VT_KEY_ENV = "VANTAGE_VT_API_KEY"
VT_BASE = "https://www.virustotal.com/api/v3"

# MISP attribute type -> the normalised kind this store keeps. MISP has a
# long tail of types; these are the ones that can actually be matched
# against the alert text this project produces. An unmapped type is counted
# and reported rather than silently dropped, so an import never quietly
# loses most of a feed.
MISP_TYPE_MAP = {
    "ip-src": "ip", "ip-dst": "ip", "ip-src|port": "ip", "ip-dst|port": "ip",
    "domain": "domain", "hostname": "domain", "domain|ip": "domain",
    "url": "url", "uri": "url",
    "md5": "hash", "sha1": "hash", "sha256": "hash",
    "filename|md5": "hash", "filename|sha1": "hash", "filename|sha256": "hash",
    "filename": "filename",
}

IOC_KINDS = ("ip", "domain", "url", "hash", "filename")


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            source TEXT NOT NULL,
            feed_event TEXT,
            category TEXT,
            comment TEXT,
            first_seen REAL NOT NULL,
            UNIQUE (kind, value, source)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_kind ON iocs(kind)")
    conn.commit()


def normalise(kind, value):
    """Normalise so a lookup matches regardless of how the feed wrote it.

    MISP composite values carry a pipe (`domain|ip`, `filename|sha256`); the
    left side is the part this store indexes for the mapped kind. Hashes and
    hostnames are case-folded because a feed and an alert will disagree
    about case sooner or later, and a store that misses on case is worse
    than no store at all — it reports "clean" with confidence.
    """
    v = str(value).strip()
    if "|" in v and kind in ("domain", "hash", "filename"):
        v = v.split("|")[0] if kind != "hash" else v.split("|")[-1]
    if kind in ("domain", "hash", "url"):
        v = v.lower()
    if kind == "ip" and "|" in v:
        v = v.split("|")[0]
    return v.strip()


# --------------------------------------------------------------------------
# Ingestion
# --------------------------------------------------------------------------

def fetch(path_or_url, timeout=15):
    """Read a feed from a local path or an http(s) URL."""
    s = str(path_or_url)
    if s.startswith(("http://", "https://")):
        import requests
        r = requests.get(s, timeout=timeout)
        r.raise_for_status()
        return r.text
    return Path(s).read_text(encoding="utf-8")


def parse_misp(text):
    """Parse MISP event JSON into (kind, value, category, comment, event_info).

    Accepts the three shapes a MISP export actually arrives in: a single
    {"Event": {...}}, a {"response": [{"Event": {...}}, ...]} bundle, and a
    bare list of events. Guessing one shape and failing on the others is how
    a feed importer ends up silently importing nothing.
    """
    data = json.loads(text)

    if isinstance(data, dict) and "response" in data:
        events = data["response"]
    elif isinstance(data, list):
        events = data
    else:
        events = [data]

    out, unmapped = [], {}
    for wrapper in events:
        ev = wrapper.get("Event", wrapper) if isinstance(wrapper, dict) else {}
        info = ev.get("info") or ev.get("uuid") or "unnamed MISP event"
        attrs = list(ev.get("Attribute") or [])
        # Attributes can also hang off objects rather than the event root.
        for obj in ev.get("Object") or []:
            attrs.extend(obj.get("Attribute") or [])
        for a in attrs:
            if not isinstance(a, dict):
                continue
            mtype = a.get("type")
            kind = MISP_TYPE_MAP.get(mtype)
            if not kind:
                unmapped[mtype] = unmapped.get(mtype, 0) + 1
                continue
            value = normalise(kind, a.get("value", ""))
            if not value:
                continue
            out.append((kind, value, a.get("category"), a.get("comment"), info))
    return out, unmapped


def import_iocs(conn, rows, source):
    """Insert indicators. Returns (added, duplicates).

    INSERT OR IGNORE on (kind, value, source) makes re-importing the same
    feed a no-op, which matters because the obvious way to use this is on a
    schedule.
    """
    added = 0
    now = time.time()
    for kind, value, category, comment, feed_event in rows:
        cur = conn.execute(
            "INSERT OR IGNORE INTO iocs "
            "(kind, value, source, feed_event, category, comment, first_seen) "
            "VALUES (?,?,?,?,?,?,?)",
            (kind, value, source, feed_event, category, comment, now))
        added += cur.rowcount
    conn.commit()
    return added, len(rows) - added


def import_plain_list(conn, path_or_url, kind, source=None):
    """Import a newline-delimited list. Lines starting with # are comments."""
    if kind not in IOC_KINDS:
        raise ValueError(f"kind must be one of {IOC_KINDS}")
    text = fetch(path_or_url)
    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append((kind, normalise(kind, line), None, None, "plain list"))
    return import_iocs(conn, rows, source or str(path_or_url))


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\\)]+", re.I)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.I)


def candidates(text):
    """Pull matchable values out of free text, normalised the same way the
    store normalises on import — otherwise the two sides never meet."""
    out = set()
    for v in IP_RE.findall(text):
        out.add(("ip", v))
    for v in URL_RE.findall(text):
        out.add(("url", v.rstrip(".,;:").lower()))
    for v in DOMAIN_RE.findall(text):
        low = v.lower()
        if not IP_RE.fullmatch(v):
            out.add(("domain", low))
    for v in HASH_RE.findall(text):
        out.add(("hash", v.lower()))
    return out


def lookup(conn, value):
    v = str(value).strip().lower()
    return conn.execute(
        "SELECT * FROM iocs WHERE lower(value) = ? ORDER BY first_seen", (v,)
    ).fetchall()


def match_text(conn, text):
    """Return every IOC hit in a block of free text (e.g. an alert message)."""
    hits = []
    for kind, value in candidates(text):
        for row in conn.execute(
            "SELECT * FROM iocs WHERE kind = ? AND lower(value) = ?",
            (kind, value.lower()),
        ):
            hits.append(dict(row))
    return hits


# --------------------------------------------------------------------------
# VirusTotal — the one component that cannot be verified from here
# --------------------------------------------------------------------------

def vt_lookup(value, api_key=None, base=None, timeout=15):
    """Query VirusTotal for a hash, domain or IP.

    Returns a dict that always includes `configured` and `error`, so a
    caller can tell "no key" apart from "looked up, nothing found" — a
    distinction an enrichment pipeline must not blur, because conflating
    them reports a clean verdict it never actually obtained.
    """
    key = api_key or os.environ.get(VT_KEY_ENV)
    if not key:
        return {"configured": False, "error": f"{VT_KEY_ENV} is not set",
                "value": value, "malicious": None}

    base = base or VT_BASE
    if HASH_RE.fullmatch(value):
        endpoint = f"{base}/files/{value}"
    elif IP_RE.fullmatch(value):
        endpoint = f"{base}/ip_addresses/{value}"
    else:
        endpoint = f"{base}/domains/{value}"

    try:
        import requests
        r = requests.get(endpoint, headers={"x-apikey": key}, timeout=timeout)
        if r.status_code == 404:
            return {"configured": True, "error": None, "value": value,
                    "malicious": 0, "found": False}
        if r.status_code == 401:
            return {"configured": True, "error": "rejected: bad API key",
                    "value": value, "malicious": None}
        if r.status_code == 429:
            return {"configured": True, "error": "rate limited (free tier is 4/min)",
                    "value": value, "malicious": None}
        r.raise_for_status()
        stats = (r.json().get("data", {}).get("attributes", {})
                 .get("last_analysis_stats", {}) or {})
        return {"configured": True, "error": None, "value": value, "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0)}
    except Exception as e:
        return {"configured": True, "error": f"{type(e).__name__}: {e}",
                "value": value, "malicious": None}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_stats(conn):
    total = conn.execute("SELECT COUNT(*) c FROM iocs").fetchone()["c"]
    print(f"=== IOC store ({total} indicator(s)) ===\n")
    if not total:
        print("  Empty — import a feed with --import-misp or --import-list.")
        return
    print("By kind:")
    for r in conn.execute("SELECT kind, COUNT(*) c FROM iocs GROUP BY kind ORDER BY c DESC"):
        print(f"  {r['kind']:10} {r['c']}")
    print("\nBy source:")
    for r in conn.execute("SELECT source, COUNT(*) c FROM iocs GROUP BY source ORDER BY c DESC LIMIT 10"):
        print(f"  {r['source'][:48]:50} {r['c']}")


def self_test():
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    print("=== IOC store self-test ===\n")
    print("  Outbound network is not required or used. The HTTP ingestion path")
    print("  and the VirusTotal path are both exercised against local servers")
    print("  serving real-shaped documents — which proves the parsing and the")
    print("  error handling, and proves nothing about any live service.\n")

    conn = connect()
    before = conn.execute("SELECT COALESCE(MAX(id),0) m FROM iocs").fetchone()["m"]

    # A real-shaped MISP export: the {"response": [...]} bundle form, with an
    # Object-nested attribute and an unmappable type, because real feeds have
    # all three.
    misp = {
        "response": [
            {"Event": {
                "uuid": "5f8c-demo", "info": SELF_TEST_MARKER + " campaign",
                "Attribute": [
                    {"type": "ip-dst", "value": "198.51.100.7", "category": "Network activity"},
                    {"type": "domain", "value": "Evil-Example.NET", "category": "Network activity"},
                    {"type": "sha256",
                     "value": "a" * 64, "category": "Payload delivery"},
                    {"type": "btc", "value": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"},
                ],
                "Object": [
                    {"Attribute": [
                        {"type": "url", "value": "http://evil-example.net/stage2",
                         "category": "Network activity"}]}
                ],
            }}
        ]
    }
    payload = json.dumps(misp)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/misp"):
                body = payload.encode()
            else:
                # VirusTotal response shape, for the VT path only.
                body = json.dumps({"data": {"attributes": {"last_analysis_stats": {
                    "malicious": 7, "suspicious": 1, "harmless": 60}}}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 8792), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    checks = []
    try:
        # 1. Parse all three MISP shapes' worth of structure.
        rows, unmapped = parse_misp(payload)
        kinds = sorted({k for k, *_ in rows})
        checks.append(("MISP parse pulls ip, domain, hash and url",
                       kinds == ["domain", "hash", "ip", "url"]))
        checks.append(("an attribute nested under Object is not missed",
                       any(v == "http://evil-example.net/stage2" for _, v, *_ in rows)))
        checks.append(("an unmappable MISP type is counted, not silently dropped",
                       unmapped.get("btc") == 1))
        checks.append(("a mixed-case domain is normalised on import",
                       any(v == "evil-example.net" for k, v, *_ in rows if k == "domain")))

        # 2. Ingest over real HTTP from the local server.
        text = fetch("http://127.0.0.1:8792/misp")
        rows2, _ = parse_misp(text)
        added, dupes = import_iocs(conn, rows2, SELF_TEST_MARKER)
        checks.append(("feed ingested over real HTTP and stored", added == len(rows2) and added > 0))

        # 3. Re-import is a no-op — this is meant to run on a schedule.
        added2, _ = import_iocs(conn, rows2, SELF_TEST_MARKER)
        checks.append(("re-importing the same feed adds nothing (idempotent)", added2 == 0))

        # 4. Match against alert-shaped free text.
        hits = match_text(conn, "c2 beacon to 198.51.100.7 every 1.5s — HIGH")
        checks.append(("an IP in alert text matches the store",
                       any(h["value"] == "198.51.100.7" for h in hits)))

        hits = match_text(conn, "DNS query for EVIL-EXAMPLE.NET observed")
        checks.append(("case-insensitive domain match (feed and alert disagree on case)",
                       any(h["value"] == "evil-example.net" for h in hits)))

        clean = match_text(conn, "connection to example.com, nothing unusual")
        checks.append(("benign text matches nothing (the control)", clean == []))

        # 5. VT: unconfigured must be distinguishable from "looked up, clean".
        unconf = vt_lookup("8.8.8.8", api_key=None)
        checks.append(("VirusTotal without a key reports not-configured, not 'clean'",
                       unconf["configured"] is False and unconf["malicious"] is None))

        configured = vt_lookup("a" * 64, api_key="test-key",
                               base="http://127.0.0.1:8792/vt")
        checks.append(("VirusTotal response parsing handles a real-shaped reply",
                       configured["configured"] is True
                       and configured["error"] is None
                       and configured["malicious"] == 7))
    finally:
        server.shutdown()
        conn.execute("DELETE FROM iocs WHERE source = ?", (SELF_TEST_MARKER,))
        conn.commit()

    print()
    for label, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    passed = all(ok for _, ok in checks)

    left = conn.execute("SELECT COUNT(*) c FROM iocs WHERE source = ?",
                        (SELF_TEST_MARKER,)).fetchone()["c"]
    print(f"\n  Cleanup: removed every test indicator ({left} left); "
          f"IOCs imported from real feeds are untouched.")
    conn.close()

    print(f"\nSelf-test {'PASSED' if passed else 'FAILED'}")
    return 0 if passed else 1


def main():
    p = argparse.ArgumentParser(description="Local IOC store that speaks the MISP event format.")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--import-misp", metavar="FILE_OR_URL")
    p.add_argument("--import-list", metavar="FILE_OR_URL")
    p.add_argument("--type", choices=list(IOC_KINDS), help="Kind for --import-list")
    p.add_argument("--source", help="Label for the imported indicators")
    p.add_argument("--lookup", metavar="VALUE")
    p.add_argument("--match", metavar="TEXT", help="Find IOCs inside a block of text")
    p.add_argument("--stats", action="store_true")
    p.add_argument("--vt", metavar="VALUE", help=f"VirusTotal lookup (needs {VT_KEY_ENV})")
    args = p.parse_args()

    if args.self_test:
        return self_test()
    if not any([args.import_misp, args.import_list, args.lookup, args.match,
                args.stats, args.vt]):
        p.error("pass one of --self-test, --import-misp, --import-list, "
                "--lookup, --match, --stats, --vt")

    conn = connect()
    if args.import_misp:
        rows, unmapped = parse_misp(fetch(args.import_misp))
        added, dupes = import_iocs(conn, rows, args.source or str(args.import_misp))
        print(f"Imported {added} new indicator(s), {dupes} already present.")
        if unmapped:
            print(f"  {sum(unmapped.values())} attribute(s) of unmapped type(s) skipped: "
                  f"{', '.join(sorted(unmapped))}")
    if args.import_list:
        if not args.type:
            p.error("--import-list needs --type")
        added, dupes = import_plain_list(conn, args.import_list, args.type, args.source)
        print(f"Imported {added} new {args.type} indicator(s), {dupes} already present.")
    if args.lookup:
        rows = lookup(conn, args.lookup)
        print(f"=== {len(rows)} hit(s) for {args.lookup} ===")
        for r in rows:
            print(f"  [{r['kind']}] {r['value']}  source={r['source']}  "
                  f"event={r['feed_event']}  category={r['category']}")
        if not rows:
            print("  Not in the store. That is not 'benign' — it means this store "
                  "has no opinion.")
    if args.match:
        hits = match_text(conn, args.match)
        print(f"=== {len(hits)} IOC hit(s) in the supplied text ===")
        for h in hits:
            print(f"  [{h['kind']}] {h['value']}  source={h['source']}")
            emit(source="ioc_store", technique_id="", severity="HIGH",
                 message=f"known-bad {h['kind']} {h['value']} (feed: {h['source']})")
    if args.stats:
        cmd_stats(conn)
    if args.vt:
        res = vt_lookup(args.vt)
        if not res["configured"]:
            print(f"VirusTotal not configured: {res['error']}")
            print(f"  export {VT_KEY_ENV}=<your key>   (free tier: 4 lookups/minute)")
        elif res["error"]:
            print(f"VirusTotal lookup failed: {res['error']}")
        else:
            print(f"VirusTotal {args.vt}: malicious={res['malicious']} "
                  f"suspicious={res.get('suspicious')} harmless={res.get('harmless')}")
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
