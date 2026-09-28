#!/usr/bin/env python
"""
SOAR playbook runner — automated enrichment and case creation on top of
the event bus.

The honest framing, same as case-management/: this is not a Cortex XSOAR
or Swimlane integration. Those are licensed server platforms. What's
implemented is the function they perform — a trigger-matched sequence of
actions that fires on an alert without a human in the loop — wired to the
modules this project already has.

It closes a gap the README had listed as genuinely open: "an
IOC-enrichment pipeline chaining domain_age_checker.py and
phishing_url_analyzer.py automatically against anything exfil_demo.py's
DLP catches." That chain existed only as a thing a human could do by hand
in three terminals. Here it's a playbook.

Playbooks are YAML in soar/playbooks/, not Python, for a specific reason:
a playbook is configuration a SOC analyst should be able to change without
touching code, and keeping them declarative is what makes the trigger
matching testable in isolation.

Two properties worth calling out because they're what makes this safe to
leave running:

  - Idempotent. Every (event, playbook) pair that runs is recorded in a
    soar_runs table; an event is never enriched twice. --watch therefore
    polls without re-doing work, and a crash mid-run resumes cleanly.
  - Observe-only. Actions enrich, correlate and open cases. Nothing here
    quarantines a file, kills a process or blocks an address — the same
    no-destructive-action boundary the rest of the project holds to. A
    real SOAR would do containment; this one deliberately doesn't, and
    that's a scope decision, not an unfinished feature.

Network honesty: check_domain_age performs a live WHOIS lookup, so it
needs outbound network and its result depends on the registry. Every other
action is fully local. --offline skips the network actions and says so,
which is also how --self-test runs — so the self-test asserts real
enrichment output (the URL analysis is pure string work) rather than
asserting something that only holds when the network cooperates.

Usage:
    python soar/playbook_runner.py --self-test
    python soar/playbook_runner.py --list-playbooks
    python soar/playbook_runner.py --run-once
    python soar/playbook_runner.py --run-once --offline
    python soar/playbook_runner.py --watch --interval 10
"""
import argparse
import contextlib
import importlib.util
import io
import re
import sqlite3
import sys
import time
from pathlib import Path

import yaml

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

PLAYBOOK_DIR = Path(__file__).resolve().parent / "playbooks"
DB_PATH = PROJECT_ROOT / "event-bus" / "events.db"

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
NETWORK_ACTIONS = {"check_domain_age"}
SELF_TEST_MARKER = "soar_self_test"

# Indicator extraction. Deliberately conservative: a greedy "anything with
# a dot" domain pattern turns every version string and filename in an alert
# message into an indicator, which is how enrichment pipelines end up
# doing thousands of pointless WHOIS lookups. The TLD here is required to
# be 2+ alphabetic characters and the whole match word-bounded, which still
# over-matches things like "exfil_demo.py" — so extract_indicators filters
# known file extensions out explicitly rather than pretending the regex is
# sufficient.
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>\\)]+", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
HASH_RE = re.compile(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", re.I)
# The leading \b here is deliberately absent on the POSIX branch. With it,
# "/home/user/x" matched as "/user/x": \b holds between "home" and the
# SECOND slash but not before the first (space-to-slash is two non-word
# characters, which is not a boundary), so the regex silently ate the
# first path component. Caught by running the ransomware playbook against
# a real alert, not by reading the pattern. The lookbehind below anchors
# on "not preceded by a path character" instead, which is what was meant.
PATH_RE = re.compile(r"(?:[A-Za-z]:\\[^\s\"'<>]+|(?<![\w.-])/(?:[\w.-]+/)+[\w.-]*)")

NON_DOMAIN_SUFFIXES = {
    ".py", ".txt", ".exe", ".dll", ".log", ".json", ".yml", ".yaml", ".pcap",
    ".db", ".bin", ".encrypted", ".ps1", ".bat", ".cmd", ".md", ".spec",
}


@contextlib.contextmanager
def muted():
    """Silences a module's own stdout while it's called as a library.

    The enrichment modules are CLI tools first — they print their findings.
    Called from a playbook they'd interleave their console output with the
    runner's, printing every finding twice in two different formats. Same
    contextlib.redirect_stdout approach scorecard/ already uses to call
    these modules programmatically.
    """
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        yield buf


def load_module(rel_path):
    """Import a module from a hyphenated directory — the same importlib
    pattern scorecard/attack_simulation_scorecard.py established, since
    'initial-access' and 'resource-development' aren't valid package names."""
    path = PROJECT_ROOT / rel_path
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------
# Playbook loading and trigger matching
# --------------------------------------------------------------------------

def load_playbooks():
    if not PLAYBOOK_DIR.is_dir():
        print(f"No playbook directory at {PLAYBOOK_DIR}")
        sys.exit(1)
    books = []
    for path in sorted(PLAYBOOK_DIR.glob("*.yml")) + sorted(PLAYBOOK_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            print(f"  [skip] {path.name}: invalid YAML — {e}")
            continue
        if not isinstance(data, dict) or "name" not in data or "actions" not in data:
            print(f"  [skip] {path.name}: needs at least 'name' and 'actions'")
            continue
        unknown = [a for a in data["actions"] if a not in ACTIONS]
        if unknown:
            # A playbook referencing an action that doesn't exist is a
            # silent no-op at runtime, which is the worst failure mode
            # automation can have. Refuse it at load time instead.
            print(f"  [skip] {path.name}: unknown action(s) {unknown} "
                  f"(known: {sorted(ACTIONS)})")
            continue
        data["_file"] = path.name
        books.append(data)
    return books


def matches(playbook, event):
    """True if this event should fire this playbook."""
    trig = playbook.get("trigger") or {}
    if "source" in trig and event["source"] != trig["source"]:
        return False
    if "technique_id" in trig:
        # Prefix match so a playbook triggering on T1059 also catches
        # T1059.001 — sub-techniques are the same technique.
        if not str(event["technique_id"] or "").startswith(str(trig["technique_id"])):
            return False
    if "min_severity" in trig:
        floor = SEVERITY_ORDER.get(str(trig["min_severity"]).upper(), 0)
        if SEVERITY_ORDER.get(str(event["severity"]).upper(), 0) < floor:
            return False
    if "message_contains" in trig:
        if str(trig["message_contains"]).lower() not in str(event["message"]).lower():
            return False
    return True


# --------------------------------------------------------------------------
# Actions. Each takes (ctx) and returns a list of human-readable result
# lines. ctx carries the event, the accumulated indicators, and the flags.
# --------------------------------------------------------------------------

def action_extract_indicators(ctx):
    text = ctx["event"]["message"]
    urls = URL_RE.findall(text)
    # Trailing punctuation is part of the sentence, not the URL.
    urls = [u.rstrip(".,;:") for u in urls]
    ips = IPV4_RE.findall(text)

    domains = set()
    for d in DOMAIN_RE.findall(text):
        low = d.lower()
        if any(low.endswith(suf) for suf in NON_DOMAIN_SUFFIXES):
            continue
        if IPV4_RE.fullmatch(d):
            continue
        domains.add(low)
    # A domain already covered by an extracted URL isn't a separate
    # indicator — enriching both would double every lookup.
    for u in urls:
        host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split(":")[0].lower()
        domains.discard(host)

    # Paths are extracted from the message with URLs blanked out first.
    # Without this, "http://example.com/a/b" yields a bogus path
    # "/example.com/a/b" — the URL's own path component masquerading as a
    # filesystem location, which would then be handed to the YARA scanner.
    residual = URL_RE.sub(" ", text)

    ctx["indicators"] = {
        "urls": urls,
        "ips": sorted(set(ips)),
        "domains": sorted(domains),
        "hashes": sorted(set(h.lower() for h in HASH_RE.findall(text))),
        "paths": sorted(set(PATH_RE.findall(residual))),
    }
    found = {k: v for k, v in ctx["indicators"].items() if v}
    if not found:
        return ["no indicators found in the alert message"]
    return [f"{k}: {', '.join(v)}" for k, v in found.items()]


def action_analyze_urls(ctx):
    urls = ctx["indicators"].get("urls", [])
    # A bare domain is still worth structural analysis (typosquat check
    # doesn't need a scheme), so feed those through too.
    targets = urls + [d for d in ctx["indicators"].get("domains", [])]
    if not targets:
        return ["no URLs or domains to analyze"]

    analyzer = load_module("initial-access/phishing_url_analyzer.py")
    lines = []
    for t in targets:
        with muted():
            findings = analyzer.analyze(t) or []
        if findings:
            for sev, reason in findings:
                lines.append(f"{t} -> [{sev}] {reason}")
                ctx["max_severity"] = max(
                    ctx["max_severity"], SEVERITY_ORDER.get(sev, 0))
        else:
            lines.append(f"{t} -> no structural red flags")
    return lines


def action_check_domain_age(ctx):
    if ctx["offline"]:
        return ["skipped: --offline (WHOIS needs outbound network)"]
    hosts = set(ctx["indicators"].get("domains", []))
    for u in ctx["indicators"].get("urls", []):
        host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split(":")[0]
        if not IPV4_RE.fullmatch(host):
            hosts.add(host.lower())
    if not hosts:
        return ["no domains to age"]

    checker = load_module("resource-development/domain_age_checker.py")
    lines = []
    for h in sorted(hosts):
        try:
            with muted():
                res = checker.check_domain(h) or {}
        except Exception as e:
            # Never let one failed lookup abort a playbook run.
            lines.append(f"{h} -> lookup raised {type(e).__name__}: {e}")
            continue
        if res.get("error"):
            lines.append(f"{h} -> lookup failed: {res['error']}")
        elif res.get("suspicious"):
            lines.append(f"{h} -> registered {res['age_days']}d ago — SUSPICIOUS")
            ctx["max_severity"] = max(ctx["max_severity"], SEVERITY_ORDER["MEDIUM"])
        else:
            lines.append(f"{h} -> {res.get('age_days')}d old, above threshold")
    return lines


def action_yara_scan(ctx):
    paths = ctx["indicators"].get("paths", [])
    if not paths:
        return ["no filesystem path in the alert to scan"]

    scanner = load_module("dfir/yara_scanner.py")
    try:
        import yara  # noqa: F401
    except ImportError:
        return ["skipped: yara-python not installed"]
    rules = scanner.compile_rules(__import__("yara"), quiet=True)

    lines = []
    for raw in paths:
        p = Path(raw)
        if not p.exists():
            lines.append(f"{raw} -> path no longer exists (nothing to scan)")
            continue
        hits = scanner.run_scan(rules, p, quiet=True, emit_events=False)
        if hits:
            for hit_path, m in hits:
                lines.append(f"{hit_path.name} -> {m.rule}")
                ctx["max_severity"] = max(
                    ctx["max_severity"],
                    SEVERITY_ORDER.get(str(m.meta.get("severity", "MEDIUM")).upper(), 2))
        else:
            lines.append(f"{raw} -> scanned, no rule matches")
    return lines


def action_open_case(ctx):
    cm = load_module("case-management/case_manager.py")
    conn = ctx["conn"]
    cm.init_db(conn)

    ev = ctx["event"]
    sev_name = next(k for k, v in SEVERITY_ORDER.items() if v == ctx["max_severity"])
    enrichment = "\n".join(f"  {line}" for line in ctx["log"])

    # Correlate before creating. Without this, a burst of related alerts —
    # which is exactly what a DLP hit or a ransomware run produces — opens
    # one case per alert, and the analyst gets the same alert list they had
    # before case management existed, only with case numbers on it. Found by
    # running this runner and case_manager --auto-triage over the same live
    # events: the runner made one case per event while auto-triage grouped
    # them, so the two disagreed about what an incident was.
    existing = cm.find_open_case_for(conn, ev["source"], ev["technique_id"])
    if existing is not None:
        cm.link_events(conn, existing, [ev["id"]])
        cm.append_note(
            conn, existing,
            f"Event #{ev['id']} correlated in by playbook "
            f"'{ctx['playbook']['name']}':\n{enrichment}")
        cm.escalate_severity(conn, existing, sev_name)
        ctx["case_id"] = existing
        return [f"correlated event #{ev['id']} into existing case #{existing} "
                f"(same source+technique, still open)"]

    title = f"[{ctx['playbook']['name']}] {ev['source']}: {ev['message'][:70]}"
    notes = (f"Opened automatically by SOAR playbook '{ctx['playbook']['name']}' "
             f"({ctx['playbook']['_file']}) from event #{ev['id']}.\n" + enrichment)
    case_id = cm.open_case(conn, title, severity=sev_name, notes=notes)
    cm.link_events(conn, case_id, [ev["id"]])
    ctx["case_id"] = case_id
    return [f"opened case #{case_id} [{sev_name}] and linked event #{ev['id']}"]


ACTIONS = {
    "extract_indicators": action_extract_indicators,
    "analyze_urls": action_analyze_urls,
    "check_domain_age": action_check_domain_age,
    "yara_scan": action_yara_scan,
    "open_case": action_open_case,
}


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS soar_runs (
            event_id INTEGER NOT NULL,
            playbook TEXT NOT NULL,
            ran_at REAL NOT NULL,
            case_id INTEGER,
            outcome TEXT,
            PRIMARY KEY (event_id, playbook)
        )
    """)
    conn.commit()


def run_playbook(conn, playbook, event, offline=False, quiet=False):
    ctx = {
        "conn": conn,
        "event": event,
        "playbook": playbook,
        "offline": offline,
        "indicators": {},
        "log": [],
        "max_severity": SEVERITY_ORDER.get(str(event["severity"]).upper(), 0),
        "case_id": None,
    }
    if not quiet:
        print(f"\n  ▸ {playbook['name']} on event #{event['id']} "
              f"[{event['severity']}] {event['source']}")

    for action_name in playbook["actions"]:
        fn = ACTIONS[action_name]
        try:
            lines = fn(ctx)
        except Exception as e:
            # One broken action must not lose the rest of the playbook, and
            # must never be silent — the failure goes in the case notes.
            lines = [f"ACTION FAILED: {type(e).__name__}: {e}"]
        for line in lines:
            ctx["log"].append(f"{action_name}: {line}")
            if not quiet:
                print(f"      {action_name:20} {line}")

    conn.execute(
        "INSERT OR REPLACE INTO soar_runs (event_id, playbook, ran_at, case_id, outcome) "
        "VALUES (?,?,?,?,?)",
        (event["id"], playbook["name"], time.time(), ctx["case_id"],
         "; ".join(ctx["log"])[:2000]),
    )
    conn.commit()

    emit(source="soar_runner",
         technique_id=event["technique_id"] or "",
         severity="INFO",
         message=f"playbook '{playbook['name']}' ran on event #{event['id']}"
                 + (f", opened case #{ctx['case_id']}" if ctx["case_id"] else ""))
    return ctx


def pending_work(conn, playbooks, limit=200):
    """Yields (playbook, event) pairs not yet recorded in soar_runs."""
    events = conn.execute(
        "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    done = {(r["event_id"], r["playbook"]) for r in
            conn.execute("SELECT event_id, playbook FROM soar_runs")}
    work = []
    for ev in reversed(events):
        for pb in playbooks:
            if (ev["id"], pb["name"]) in done:
                continue
            if matches(pb, ev):
                work.append((pb, ev))
    return work


def run_once(conn, playbooks, offline=False, quiet=False):
    work = pending_work(conn, playbooks)
    if not work:
        if not quiet:
            print("  Nothing pending — every matching event has already been "
                  "run through its playbook(s).")
        return 0
    for pb, ev in work:
        run_playbook(conn, pb, ev, offline=offline, quiet=quiet)
    return len(work)


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def self_test():
    print("=== SOAR playbook runner self-test ===\n")
    print("  Running --offline: WHOIS depends on outbound network and on what a")
    print("  registry chooses to return, so asserting on it would make this test")
    print("  flaky for reasons that have nothing to do with the orchestration.")
    print("  Every other action is local, so their output IS asserted.\n")

    playbooks = load_playbooks()
    print(f"  Loaded {len(playbooks)} playbook(s): {', '.join(p['name'] for p in playbooks)}\n")

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cm = load_module("case-management/case_manager.py")
    cm.init_db(conn)
    init_db(conn)

    now = time.time()
    fixtures = [
        # Should fire phishing-url-triage (T1566, MEDIUM floor). The URL is a
        # typosquat the offline analyzer will genuinely flag HIGH.
        (now - 10, SELF_TEST_MARKER, "T1566", "HIGH",
         "user clicked https://www.paypa1.com/login from an email"),
        # Should fire nothing: LOW is under every trigger's floor.
        (now - 9, SELF_TEST_MARKER, "T1082", "LOW", "routine host enumeration"),
    ]
    seeded = []
    for ts, src, tid, sev, msg in fixtures:
        cur = conn.execute(
            "INSERT INTO events (timestamp, source, technique_id, severity, message) "
            "VALUES (?,?,?,?,?)", (ts, src, tid, sev, msg))
        seeded.append(cur.lastrowid)
    conn.commit()
    print(f"  Seeded {len(seeded)} marker event(s) (source='{SELF_TEST_MARKER}')")

    before_cases = {r["id"] for r in conn.execute("SELECT id FROM cases")}

    # Only consider work for the events this test seeded, so a developer's
    # real un-processed history isn't dragged into the assertions.
    work = [(pb, ev) for pb, ev in pending_work(conn, playbooks) if ev["id"] in seeded]
    matched_names = sorted({pb["name"] for pb, _ in work})
    print(f"\n  Trigger matching: {len(work)} (playbook, event) pair(s) -> {matched_names}")

    contexts = []
    for pb, ev in work:
        contexts.append(run_playbook(conn, pb, ev, offline=True, quiet=True))

    checks = []
    checks.append(("only the T1566 HIGH event matched a playbook",
                   len(work) == 1 and work[0][1]["id"] == seeded[0]))
    checks.append(("the LOW event matched nothing",
                   all(ev["id"] != seeded[1] for _, ev in work)))

    ctx = contexts[0] if contexts else None
    checks.append(("URL extracted from the alert message",
                   bool(ctx) and ctx["indicators"]["urls"] == ["https://www.paypa1.com/login"]))
    checks.append(("no junk indicators (no bare-domain duplicate of the URL host)",
                   bool(ctx) and ctx["indicators"]["domains"] == []))

    url_findings = [l for l in (ctx["log"] if ctx else []) if l.startswith("analyze_urls:")]
    checks.append(("offline URL analysis produced a real typosquat finding",
                   any("typosquatting" in l for l in url_findings)))

    checks.append(("network action skipped and said so under --offline",
                   any("skipped: --offline" in l for l in (ctx["log"] if ctx else []))))

    new_cases = [r["id"] for r in conn.execute("SELECT id FROM cases")
                 if r["id"] not in before_cases]
    checks.append(("a case was opened and linked to the triggering event",
                   bool(ctx) and ctx["case_id"] in new_cases
                   and seeded[0] in cm.case_event_ids(conn, ctx["case_id"])))

    # Severity escalation: the event was HIGH, the URL finding was HIGH, and
    # the case should carry HIGH rather than the playbook's default.
    if ctx and ctx["case_id"]:
        case_row = conn.execute("SELECT severity FROM cases WHERE id = ?",
                                (ctx["case_id"],)).fetchone()
        checks.append(("case severity reflects the enrichment result",
                       case_row["severity"] == "HIGH"))

    print("\n  Re-running (must be a no-op)...")
    work2 = [(pb, ev) for pb, ev in pending_work(conn, playbooks) if ev["id"] in seeded]
    print(f"    {len(work2)} pending pair(s)")
    checks.append(("re-run found nothing pending (idempotent)", len(work2) == 0))

    print()
    for label, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    passed = all(ok for _, ok in checks)

    # Clean up only this test's rows.
    if new_cases:
        ph = ",".join("?" * len(new_cases))
        conn.execute(f"DELETE FROM case_events WHERE case_id IN ({ph})", new_cases)
        conn.execute(f"DELETE FROM cases WHERE id IN ({ph})", new_cases)
    ph = ",".join("?" * len(seeded))
    conn.execute(f"DELETE FROM soar_runs WHERE event_id IN ({ph})", seeded)
    conn.execute("DELETE FROM events WHERE source = ?", (SELF_TEST_MARKER,))
    conn.commit()
    leftover = conn.execute("SELECT COUNT(*) c FROM events WHERE source = ?",
                            (SELF_TEST_MARKER,)).fetchone()["c"]
    print(f"\n  Cleanup: removed {len(new_cases)} test case(s), their SOAR run records "
          f"and every marker event ({leftover} left) — real history untouched.")
    conn.close()

    print(f"\nSelf-test {'PASSED' if passed else 'FAILED'}")
    return 0 if passed else 1


def cmd_list_playbooks():
    books = load_playbooks()
    print(f"\n=== {len(books)} playbook(s) in {PLAYBOOK_DIR} ===\n")
    for b in books:
        trig = b.get("trigger") or {}
        trig_str = ", ".join(f"{k}={v}" for k, v in trig.items()) or "(always)"
        print(f"  {b['name']}  [{b['_file']}]")
        print(f"      trigger:  {trig_str}")
        print(f"      actions:  {' -> '.join(b['actions'])}")
        net = [a for a in b["actions"] if a in NETWORK_ACTIONS]
        if net:
            print(f"      network:  {', '.join(net)} (skipped under --offline)")
        print(f"      {' '.join(str(b.get('description', '')).split())[:150]}")
        print()
    return 0


def main():
    p = argparse.ArgumentParser(description="Run enrichment playbooks against event-bus alerts.")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--list-playbooks", action="store_true")
    p.add_argument("--run-once", action="store_true", help="Process all pending events and exit")
    p.add_argument("--watch", action="store_true", help="Poll for new events until Ctrl+C")
    p.add_argument("--interval", type=int, default=10, help="--watch poll interval (default 10s)")
    p.add_argument("--offline", action="store_true",
                   help="Skip network-dependent actions (WHOIS) and say so")
    args = p.parse_args()

    if args.self_test:
        return self_test()
    if args.list_playbooks:
        return cmd_list_playbooks()
    if not (args.run_once or args.watch):
        p.error("pass one of --self-test, --list-playbooks, --run-once, --watch")

    if not DB_PATH.exists():
        print(f"No event database at {DB_PATH} — start event-bus/collector.py and fire "
              f"a detector first, or run --self-test.")
        return 1

    playbooks = load_playbooks()
    if not playbooks:
        print("No usable playbooks loaded.")
        return 1
    print(f"Loaded {len(playbooks)} playbook(s): {', '.join(b['name'] for b in playbooks)}")
    if args.offline:
        print("Offline mode: network actions "
              f"({', '.join(sorted(NETWORK_ACTIONS))}) will be skipped.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    init_db(conn)

    if args.run_once:
        n = run_once(conn, playbooks, offline=args.offline)
        print(f"\n  {n} playbook run(s) completed.")
        conn.close()
        return 0

    print(f"\nWatching for new events every {args.interval}s (Ctrl+C to stop)...")
    try:
        while True:
            run_once(conn, playbooks, offline=args.offline, quiet=False)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
