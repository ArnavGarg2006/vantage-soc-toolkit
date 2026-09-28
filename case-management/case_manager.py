#!/usr/bin/env python
"""
Case management — the lifecycle layer the event bus never had.

The honest framing: this is NOT a TheHive or ServiceNow SecOps
integration. Those are server platforms, and writing an API client
against an instance that doesn't exist anywhere would produce code whose
output was never verified — the one thing this project consistently
refuses to ship. What IS implemented here is the function those platforms
perform, against the SQLite store the collector already writes to.

The gap it closes, which is real: after Phase 5, every detector in this
project could emit an alert and every alert landed in one dashboard and
one durable history. But an alert is not an investigation. Nothing in
events.db could be assigned to a person, grouped with the other alerts
from the same incident, marked a false positive, or closed. A SOC that
can only ever say "here are 400 alerts" has a firehose, not a process —
and the metric that actually matters (how long does it take us to close
one, and how many turn out to be nothing) was not computable at all.

Design decisions worth stating:

  - Cases live in the SAME database as events (event-bus/events.db), not
    a second store. A case that can't be joined to the events that caused
    it in one query is a spreadsheet, not case management.
  - --auto-triage is idempotent. It groups un-cased alerts by
    (source, technique) inside a time window; an event already linked to
    a case is never pulled into a second one. Re-running it is a no-op,
    which matters because the obvious way to use it is on a timer.
  - Closing requires a disposition. "Closed" without saying whether it
    was a true positive is how a SOC loses the only feedback signal its
    detection engineering has.

Usage:
    python case-management/case_manager.py --self-test
    python case-management/case_manager.py --auto-triage
    python case-management/case_manager.py --list
    python case-management/case_manager.py --show 1
    python case-management/case_manager.py --open "Suspicious PowerShell on WS01" --severity HIGH
    python case-management/case_manager.py --assign 1 arnav
    python case-management/case_manager.py --set-status 1 IN_PROGRESS
    python case-management/case_manager.py --close 1 --disposition FALSE_POSITIVE --note "known admin script"
    python case-management/case_manager.py --link 1 17 18 19
    python case-management/case_manager.py --stats
"""
import argparse
import sqlite3
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

DB_PATH = Path(__file__).resolve().parent.parent / "event-bus" / "events.db"

STATUSES = ("OPEN", "IN_PROGRESS", "CLOSED")
DISPOSITIONS = ("TRUE_POSITIVE", "BENIGN_TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE")
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}

# Alerts this far apart are treated as separate incidents even when they
# share a source and technique. 30 minutes is a starting point, not a
# tuned value — it's exposed as --window-minutes precisely because the
# right number is environment-specific and this project won't pretend
# otherwise.
DEFAULT_WINDOW_MINUTES = 30

SELF_TEST_MARKER = "case_manager_self_test"


def connect(create_ok=True):
    if not DB_PATH.exists() and not create_ok:
        print(f"No database at {DB_PATH} — start event-bus/collector.py and fire a "
              f"detector first, or run --self-test.")
        sys.exit(1)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    """Creates the case tables alongside the collector's events table.

    Also creates `events` if it's missing, so this tool works on a fresh
    checkout without requiring the collector to have run first — same
    schema as collector.py's init_db(), deliberately identical so the two
    can never disagree about the table shape.
    """
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            source TEXT NOT NULL,
            technique_id TEXT,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN',
            severity TEXT NOT NULL DEFAULT 'MEDIUM',
            assignee TEXT,
            disposition TEXT,
            opened_at REAL NOT NULL,
            updated_at REAL NOT NULL,
            closed_at REAL,
            notes TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_events (
            case_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            linked_at REAL NOT NULL,
            PRIMARY KEY (case_id, event_id),
            FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_case_events_event ON case_events(event_id)")
    conn.commit()


# --------------------------------------------------------------------------
# Core operations — importable, so the SOAR playbook runner can open and
# annotate cases without shelling out to this CLI.
# --------------------------------------------------------------------------

def open_case(conn, title, severity="MEDIUM", assignee=None, notes=None):
    now = time.time()
    cur = conn.execute(
        "INSERT INTO cases (title, status, severity, assignee, opened_at, updated_at, notes) "
        "VALUES (?, 'OPEN', ?, ?, ?, ?, ?)",
        (title, severity.upper(), assignee, now, now, notes),
    )
    conn.commit()
    return cur.lastrowid


def link_events(conn, case_id, event_ids):
    """Links events to a case. Returns how many were newly linked.

    INSERT OR IGNORE on the composite primary key is what makes
    auto-triage safe to re-run: linking the same event twice is a no-op
    rather than a duplicate row or an exception.
    """
    now = time.time()
    linked = 0
    for eid in event_ids:
        cur = conn.execute(
            "INSERT OR IGNORE INTO case_events (case_id, event_id, linked_at) VALUES (?,?,?)",
            (case_id, eid, now),
        )
        linked += cur.rowcount
    conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (now, case_id))
    conn.commit()
    return linked


def set_status(conn, case_id, status):
    status = status.upper()
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    conn.execute("UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
                 (status, time.time(), case_id))
    conn.commit()


def assign_case(conn, case_id, assignee):
    conn.execute("UPDATE cases SET assignee = ?, updated_at = ? WHERE id = ?",
                 (assignee, time.time(), case_id))
    conn.commit()


def close_case(conn, case_id, disposition, note=None):
    disposition = disposition.upper()
    if disposition not in DISPOSITIONS:
        raise ValueError(f"disposition must be one of {DISPOSITIONS}")
    now = time.time()
    row = conn.execute("SELECT notes FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        raise ValueError(f"no case {case_id}")
    notes = row["notes"]
    if note:
        notes = f"{notes}\n{note}" if notes else note
    conn.execute(
        "UPDATE cases SET status='CLOSED', disposition=?, closed_at=?, updated_at=?, notes=? WHERE id=?",
        (disposition, now, now, notes, case_id),
    )
    conn.commit()


def case_event_ids(conn, case_id):
    return [r["event_id"] for r in conn.execute(
        "SELECT event_id FROM case_events WHERE case_id = ? ORDER BY event_id", (case_id,))]


def find_open_case_for(conn, source, technique_id, window_minutes=DEFAULT_WINDOW_MINUTES):
    """Finds an OPEN case already holding an alert from the same
    (source, technique) inside the window, or None.

    This is what stops an alert storm becoming a hundred cases. Both
    auto_triage and the SOAR playbook runner correlate on the same key,
    so a burst of related alerts converges on one investigation no matter
    which of the two got there first — which is the entire point of
    having case management rather than a list of alerts.
    """
    cutoff = time.time() - window_minutes * 60
    row = conn.execute(
        "SELECT c.id FROM cases c "
        "JOIN case_events ce ON ce.case_id = c.id "
        "JOIN events e ON e.id = ce.event_id "
        "WHERE c.status != 'CLOSED' AND e.source = ? "
        "AND COALESCE(e.technique_id,'') = COALESCE(?,'') "
        "AND e.timestamp >= ? "
        "ORDER BY c.id DESC LIMIT 1",
        (source, technique_id or "", cutoff),
    ).fetchone()
    return row["id"] if row else None


def append_note(conn, case_id, note):
    row = conn.execute("SELECT notes FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        raise ValueError(f"no case {case_id}")
    notes = f"{row['notes']}\n{note}" if row["notes"] else note
    conn.execute("UPDATE cases SET notes = ?, updated_at = ? WHERE id = ?",
                 (notes, time.time(), case_id))
    conn.commit()


def escalate_severity(conn, case_id, severity):
    """Raises a case's severity, never lowers it. A case that held a HIGH
    alert doesn't become MEDIUM because a quieter one joined it."""
    row = conn.execute("SELECT severity FROM cases WHERE id = ?", (case_id,)).fetchone()
    if row is None:
        return
    if SEVERITY_ORDER.get(severity.upper(), 0) > SEVERITY_ORDER.get(row["severity"], 0):
        conn.execute("UPDATE cases SET severity = ?, updated_at = ? WHERE id = ?",
                     (severity.upper(), time.time(), case_id))
        conn.commit()


def auto_triage(conn, window_minutes=DEFAULT_WINDOW_MINUTES, min_severity="MEDIUM", quiet=False):
    """Groups un-cased alerts into cases by (source, technique) + time window.

    Returns (cases_created, events_linked). Idempotent: an event already
    attached to any case is excluded by the NOT IN subquery, so a second
    run over the same history creates nothing.
    """
    floor = SEVERITY_ORDER.get(min_severity.upper(), 2)
    eligible = [s for s, v in SEVERITY_ORDER.items() if v >= floor]
    placeholders = ",".join("?" * len(eligible))

    rows = conn.execute(
        f"SELECT id, timestamp, source, technique_id, severity, message FROM events "
        f"WHERE severity IN ({placeholders}) "
        f"AND id NOT IN (SELECT event_id FROM case_events) "
        f"ORDER BY source, technique_id, timestamp",
        eligible,
    ).fetchall()

    if not rows:
        if not quiet:
            print("  No un-cased alerts at or above "
                  f"{min_severity.upper()} — nothing to triage.")
        return 0, 0

    window = window_minutes * 60
    groups = []
    current = None
    for r in rows:
        key = (r["source"], r["technique_id"])
        if (current is None
                or current["key"] != key
                or r["timestamp"] - current["last_ts"] > window):
            current = {"key": key, "rows": [r], "last_ts": r["timestamp"]}
            groups.append(current)
        else:
            current["rows"].append(r)
            current["last_ts"] = r["timestamp"]

    created = 0
    linked_total = 0
    for g in groups:
        source, technique = g["key"]
        members = g["rows"]
        worst = max(members, key=lambda r: SEVERITY_ORDER.get(r["severity"], 0))["severity"]
        span_min = (members[-1]["timestamp"] - members[0]["timestamp"]) / 60
        title = (f"{len(members)} {worst} alert(s) from {source}"
                 f"{' / ' + technique if technique else ''}")
        notes = (f"Auto-triaged: grouped by (source={source}, technique={technique or 'none'}) "
                 f"within a {window_minutes}-minute window. "
                 f"Span {span_min:.1f} min. First: {members[0]['message'][:120]}")
        case_id = open_case(conn, title, severity=worst, notes=notes)
        linked_total += link_events(conn, case_id, [r["id"] for r in members])
        created += 1
        if not quiet:
            print(f"  Case #{case_id} [{worst:6}] {title}")
    return created, linked_total


# --------------------------------------------------------------------------
# CLI rendering
# --------------------------------------------------------------------------

def fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "-"


def fmt_duration(seconds):
    if seconds is None:
        return "-"
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f}m"
    if seconds < 86400:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


def cmd_list(conn, status=None):
    sql = ("SELECT c.*, (SELECT COUNT(*) FROM case_events ce WHERE ce.case_id = c.id) n "
           "FROM cases c")
    params = []
    if status:
        sql += " WHERE c.status = ?"
        params.append(status.upper())
    sql += " ORDER BY c.id DESC"
    rows = conn.execute(sql, params).fetchall()

    print(f"=== {len(rows)} case(s){' with status ' + status.upper() if status else ''} ===\n")
    if not rows:
        print("  None. Run --auto-triage to build cases from un-cased alerts.")
        return
    print(f"  {'ID':>4}  {'SEV':7} {'STATUS':12} {'EVENTS':>6}  {'ASSIGNEE':12} {'OPENED':20} TITLE")
    for r in rows:
        print(f"  {r['id']:>4}  {r['severity']:7} {r['status']:12} {r['n']:>6}  "
              f"{(r['assignee'] or '-'):12} {fmt_ts(r['opened_at']):20} {r['title'][:50]}")


def cmd_show(conn, case_id):
    r = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    if r is None:
        print(f"No case #{case_id}.")
        return 1
    print(f"=== Case #{r['id']}: {r['title']} ===\n")
    print(f"  Status:      {r['status']}")
    print(f"  Severity:    {r['severity']}")
    print(f"  Assignee:    {r['assignee'] or '(unassigned)'}")
    print(f"  Opened:      {fmt_ts(r['opened_at'])}")
    print(f"  Updated:     {fmt_ts(r['updated_at'])}")
    if r["status"] == "CLOSED":
        print(f"  Closed:      {fmt_ts(r['closed_at'])}")
        print(f"  Disposition: {r['disposition']}")
        print(f"  Time to close: {fmt_duration(r['closed_at'] - r['opened_at'])}")
    if r["notes"]:
        print(f"\n  Notes:")
        for line in str(r["notes"]).splitlines():
            print(f"    {line}")

    events = conn.execute(
        "SELECT e.* FROM events e JOIN case_events ce ON ce.event_id = e.id "
        "WHERE ce.case_id = ? ORDER BY e.timestamp",
        (case_id,),
    ).fetchall()
    print(f"\n  Linked events ({len(events)}):")
    if not events:
        print("    (none)")
    for e in events:
        print(f"    #{e['id']:<5} [{fmt_ts(e['timestamp'])}] {e['severity']:6} "
              f"{e['source']:22} {(e['technique_id'] or ''):10} {e['message'][:60]}")
    return 0


def cmd_stats(conn):
    total = conn.execute("SELECT COUNT(*) c FROM cases").fetchone()["c"]
    print(f"=== Case statistics ({total} case(s)) ===\n")
    if total == 0:
        print("  No cases yet.")
        return

    print("By status:")
    for r in conn.execute("SELECT status, COUNT(*) c FROM cases GROUP BY status ORDER BY c DESC"):
        print(f"  {r['status']:14} {r['c']}")

    print("\nBy severity:")
    for r in conn.execute("SELECT severity, COUNT(*) c FROM cases GROUP BY severity ORDER BY c DESC"):
        print(f"  {r['severity']:14} {r['c']}")

    closed = conn.execute(
        "SELECT disposition, COUNT(*) c, AVG(closed_at - opened_at) avg_s "
        "FROM cases WHERE status='CLOSED' AND disposition IS NOT NULL "
        "GROUP BY disposition ORDER BY c DESC"
    ).fetchall()
    if closed:
        print("\nBy disposition (closed cases only):")
        for r in closed:
            print(f"  {r['disposition']:22} {r['c']:>4}   mean time to close {fmt_duration(r['avg_s'])}")

        fp = sum(r["c"] for r in closed if r["disposition"] in ("FALSE_POSITIVE", "DUPLICATE"))
        tot = sum(r["c"] for r in closed)
        # This is the number the detection-engineering side of this project
        # actually needs and could not compute before cases existed.
        print(f"\n  False-positive rate: {fp}/{tot} = {fp / tot * 100:.0f}% of closed cases")
    else:
        print("\n  No closed cases yet — mean-time-to-close and false-positive rate "
              "need at least one case closed with a disposition.")

    uncased = conn.execute(
        "SELECT COUNT(*) c FROM events WHERE id NOT IN (SELECT event_id FROM case_events)"
    ).fetchone()["c"]
    print(f"\n  {uncased} event(s) not attached to any case (run --auto-triage).")


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def self_test():
    print("=== Case manager self-test ===\n")
    conn = connect()
    init_db(conn)

    # Seed events with a marker source so cleanup can target exactly these
    # rows and never touch real history — same discipline collector.py's
    # self-test uses.
    now = time.time()
    seeded = []
    fixtures = [
        (now - 300, SELF_TEST_MARKER, "T1059.001", "HIGH", "encoded powershell #1"),
        (now - 290, SELF_TEST_MARKER, "T1059.001", "HIGH", "encoded powershell #2"),
        (now - 280, SELF_TEST_MARKER, "T1059.001", "MEDIUM", "encoded powershell #3"),
        # Same source+technique but 4 hours earlier — MUST land in its own
        # case, otherwise the time window isn't doing anything.
        (now - 14400, SELF_TEST_MARKER, "T1059.001", "HIGH", "encoded powershell, hours earlier"),
        # Different technique — must not be merged with the others.
        (now - 295, SELF_TEST_MARKER, "T1486", "HIGH", "mass file encryption detected"),
        # Below the MEDIUM floor — must be left un-cased.
        (now - 292, SELF_TEST_MARKER, "T1082", "LOW", "routine host enumeration"),
    ]
    for ts, src, tid, sev, msg in fixtures:
        cur = conn.execute(
            "INSERT INTO events (timestamp, source, technique_id, severity, message) VALUES (?,?,?,?,?)",
            (ts, src, tid, sev, msg))
        seeded.append(cur.lastrowid)
    conn.commit()
    print(f"  Seeded {len(seeded)} marker event(s) (source='{SELF_TEST_MARKER}')")

    print("\n  Running auto-triage...")
    auto_triage(conn, window_minutes=30, min_severity="MEDIUM", quiet=True)

    # Scope every assertion AND the cleanup to cases that actually contain a
    # seeded event, not to "whatever cases appeared while auto-triage ran".
    #
    # The naive version of this test diffed the case table before and after.
    # That passed on an empty database and broke the moment it ran against
    # one with real un-cased alerts in it: auto_triage processes the whole
    # history, so the diff swept up cases built from real events — and the
    # cleanup then DELETED them, while printing "real history untouched".
    # A self-test that can destroy the data it promises not to touch is
    # worse than no self-test. Grouping is keyed on (source, technique) and
    # the marker source is unique to this test, so no real event can ever
    # land in one of these cases.
    ph = ",".join("?" * len(seeded))
    test_cases = [r["case_id"] for r in conn.execute(
        f"SELECT DISTINCT case_id FROM case_events WHERE event_id IN ({ph})", seeded)]
    linked = conn.execute(
        f"SELECT COUNT(*) c FROM case_events WHERE event_id IN ({ph})", seeded
    ).fetchone()["c"]
    created = len(test_cases)
    new_cases = test_cases
    print(f"    {created} case(s) created from seeded events, {linked} event(s) linked")

    checks = []

    # 3 groups expected: recent T1059.001 cluster, the old T1059.001 one
    # (separated by the window), and the T1486 alert.
    checks.append(("auto-triage created 3 cases from 6 seeded events", created == 3))
    checks.append(("5 eligible events linked, LOW one left out", linked == 5))

    low_id = seeded[5]
    low_linked = conn.execute(
        "SELECT COUNT(*) c FROM case_events WHERE event_id = ?", (low_id,)).fetchone()["c"]
    checks.append(("LOW-severity event stayed un-cased", low_linked == 0))

    sizes = sorted(
        conn.execute(
            "SELECT case_id, COUNT(*) n FROM case_events WHERE case_id IN "
            f"({','.join('?' * len(new_cases))}) GROUP BY case_id", new_cases
        ).fetchall(), key=lambda r: r["n"])
    checks.append(("time window split the same technique into separate cases",
                   [r["n"] for r in sizes] == [1, 1, 3]))

    # Idempotency — the property that makes this safe on a timer.
    print("\n  Re-running auto-triage (must be a no-op for the seeded events)...")
    auto_triage(conn, window_minutes=30, min_severity="MEDIUM", quiet=True)
    cases_after = [r["case_id"] for r in conn.execute(
        f"SELECT DISTINCT case_id FROM case_events WHERE event_id IN ({ph})", seeded)]
    linked_after = conn.execute(
        f"SELECT COUNT(*) c FROM case_events WHERE event_id IN ({ph})", seeded
    ).fetchone()["c"]
    print(f"    {len(cases_after)} case(s), {linked_after} link(s) — unchanged if idempotent")
    checks.append(("re-running auto-triage changed nothing (idempotent)",
                   sorted(cases_after) == sorted(test_cases) and linked_after == linked))

    # Lifecycle.
    target = max(new_cases)
    assign_case(conn, target, "analyst-1")
    set_status(conn, target, "IN_PROGRESS")
    close_case(conn, target, "FALSE_POSITIVE", note="known admin automation")
    r = conn.execute("SELECT * FROM cases WHERE id = ?", (target,)).fetchone()
    checks.append(("assign -> in progress -> close with disposition persisted",
                   r["assignee"] == "analyst-1"
                   and r["status"] == "CLOSED"
                   and r["disposition"] == "FALSE_POSITIVE"
                   and r["closed_at"] is not None
                   and "known admin automation" in (r["notes"] or "")))

    # A close without a valid disposition must be refused — that rule is the
    # whole reason the false-positive rate is computable.
    try:
        close_case(conn, target, "WHATEVER")
        rejected = False
    except ValueError:
        rejected = True
    checks.append(("close with an invalid disposition is rejected", rejected))

    print()
    for label, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    passed = all(ok for _, ok in checks)

    # Clean up ONLY what this test made. Real cases and real events survive.
    if new_cases:
        cph = ",".join("?" * len(new_cases))
        conn.execute(f"DELETE FROM case_events WHERE case_id IN ({cph})", new_cases)
        conn.execute(f"DELETE FROM cases WHERE id IN ({cph})", new_cases)
    conn.execute("DELETE FROM events WHERE source = ?", (SELF_TEST_MARKER,))
    conn.commit()
    leftover = conn.execute(
        "SELECT COUNT(*) c FROM events WHERE source = ?", (SELF_TEST_MARKER,)).fetchone()["c"]
    print(f"\n  Cleanup: removed {len(new_cases)} test case(s) and every marker event "
          f"({leftover} left) — real history untouched.")
    conn.close()

    print(f"\nSelf-test {'PASSED' if passed else 'FAILED'}")
    return 0 if passed else 1


def main():
    p = argparse.ArgumentParser(description="Alert-to-case lifecycle on top of the event bus.")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--auto-triage", action="store_true",
                   help="Group un-cased alerts into cases (idempotent)")
    p.add_argument("--window-minutes", type=int, default=DEFAULT_WINDOW_MINUTES,
                   help=f"Auto-triage grouping window (default {DEFAULT_WINDOW_MINUTES})")
    p.add_argument("--min-severity", default="MEDIUM", choices=list(SEVERITY_ORDER),
                   help="Lowest severity auto-triage will case up (default MEDIUM)")
    p.add_argument("--list", action="store_true", help="List cases")
    p.add_argument("--status", help="Filter --list by status", choices=list(STATUSES))
    p.add_argument("--show", type=int, metavar="ID", help="Show one case and its linked events")
    p.add_argument("--open", metavar="TITLE", help="Open a case manually")
    p.add_argument("--severity", default="MEDIUM", choices=list(SEVERITY_ORDER))
    p.add_argument("--assign", nargs=2, metavar=("ID", "NAME"))
    p.add_argument("--set-status", nargs=2, metavar=("ID", "STATUS"))
    p.add_argument("--close", type=int, metavar="ID")
    p.add_argument("--disposition", choices=list(DISPOSITIONS))
    p.add_argument("--note", help="Note to append when closing")
    p.add_argument("--link", nargs="+", metavar=("CASE_ID", "EVENT_ID"),
                   help="Link event IDs to a case: --link CASE_ID EVENT_ID [EVENT_ID ...]")
    p.add_argument("--stats", action="store_true", help="Status/disposition breakdown and MTTC")
    args = p.parse_args()

    if args.self_test:
        return self_test()

    if not any([args.auto_triage, args.list, args.show, args.open, args.assign,
                args.set_status, args.close, args.link, args.stats]):
        p.error("pass one of --self-test, --auto-triage, --list, --show, --open, "
                "--assign, --set-status, --close, --link, --stats")

    conn = connect(create_ok=False)
    init_db(conn)

    if args.auto_triage:
        print(f"=== Auto-triage (window {args.window_minutes}m, "
              f"min severity {args.min_severity}) ===\n")
        created, linked = auto_triage(conn, args.window_minutes, args.min_severity)
        print(f"\n  {created} case(s) created, {linked} event(s) linked.")
    if args.open:
        cid = open_case(conn, args.open, severity=args.severity)
        print(f"Opened case #{cid} [{args.severity.upper()}] {args.open}")
    if args.assign:
        assign_case(conn, int(args.assign[0]), args.assign[1])
        print(f"Case #{args.assign[0]} assigned to {args.assign[1]}")
    if args.set_status:
        set_status(conn, int(args.set_status[0]), args.set_status[1])
        print(f"Case #{args.set_status[0]} -> {args.set_status[1].upper()}")
    if args.close:
        if not args.disposition:
            # Deliberately a hard error, not a default. See module docstring.
            p.error("--close requires --disposition "
                    f"({'/'.join(DISPOSITIONS)}) — closing without one throws away "
                    "the only feedback detection engineering gets")
        close_case(conn, args.close, args.disposition, args.note)
        print(f"Case #{args.close} CLOSED as {args.disposition}")
    if args.link:
        cid = int(args.link[0])
        n = link_events(conn, cid, [int(x) for x in args.link[1:]])
        print(f"Linked {n} new event(s) to case #{cid}")
    if args.list:
        cmd_list(conn, args.status)
    if args.show:
        cmd_show(conn, args.show)
    if args.stats:
        cmd_stats(conn)

    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
