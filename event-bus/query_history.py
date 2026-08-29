#!/usr/bin/env python
"""
Event history query tool — the analysis half of the durable SQLite store
collector.py now writes to (event-bus/events.db). A live dashboard answers
"what's happening right now"; this answers the question a point-in-time
view genuinely can't: which technique fires most on this machine, how many
HIGH-severity alerts happened this week, what's the day-by-day trend.

Read-only against the same database the collector writes to — safe to run
at any time, including while the collector is live (SQLite handles
concurrent readers/writers on its own; nothing here blocks or interferes
with the collector's own writes).

Usage:
    python query_history.py --summary
    python query_history.py --top-techniques 5
    python query_history.py --since-days 7
    python query_history.py --technique T1486
    python query_history.py --trend 7
"""
import argparse
import sqlite3
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

DB_PATH = Path(__file__).resolve().parent / "events.db"


def connect():
    if not DB_PATH.exists():
        print(f"No event history yet at {DB_PATH} — run collector.py and fire some wired "
              f"detectors first (see README's Phase 5 usage examples).")
        sys.exit(1)
    return sqlite3.connect(DB_PATH)


def cmd_summary(conn):
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    print(f"=== Event history summary ({total} total event(s)) ===\n")
    if total == 0:
        print("  Empty — nothing persisted yet.")
        return

    print("By severity:")
    for sev, count in conn.execute(
        "SELECT severity, COUNT(*) c FROM events GROUP BY severity ORDER BY c DESC"
    ):
        print(f"  {sev:8} {count}")

    print("\nBy source:")
    for src, count in conn.execute(
        "SELECT source, COUNT(*) c FROM events GROUP BY source ORDER BY c DESC"
    ):
        print(f"  {src:28} {count}")

    first, last = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM events").fetchone()
    print(f"\nSpan: {time.ctime(first)}  ->  {time.ctime(last)}")


def cmd_top_techniques(conn, n):
    print(f"=== Top {n} technique(s) by event count ===\n")
    rows = conn.execute(
        "SELECT technique_id, COUNT(*) c FROM events WHERE technique_id != '' "
        "GROUP BY technique_id ORDER BY c DESC LIMIT ?",
        (n,),
    ).fetchall()
    if not rows:
        print("  No technique-tagged events yet.")
        return
    for tid, count in rows:
        print(f"  {tid:14} {count}")


def cmd_since_days(conn, days):
    cutoff = time.time() - days * 86400
    rows = conn.execute(
        "SELECT timestamp, severity, source, technique_id, message FROM events "
        "WHERE timestamp >= ? ORDER BY timestamp DESC",
        (cutoff,),
    ).fetchall()
    print(f"=== {len(rows)} event(s) in the last {days} day(s) ===\n")
    for ts, sev, src, tid, msg in rows:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        print(f"  [{stamp}] {sev:6} {src:24} {tid:12} {msg[:70]}")


def cmd_technique(conn, technique_id):
    rows = conn.execute(
        "SELECT timestamp, severity, source, message FROM events "
        "WHERE technique_id = ? ORDER BY timestamp DESC",
        (technique_id,),
    ).fetchall()
    print(f"=== {len(rows)} event(s) for {technique_id} ===\n")
    if not rows:
        print("  Nothing on record for this technique yet.")
        return
    for ts, sev, src, msg in rows:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        print(f"  [{stamp}] {sev:6} {src:24} {msg[:80]}")


def cmd_trend(conn, days):
    cutoff = time.time() - days * 86400
    rows = conn.execute(
        "SELECT date(timestamp, 'unixepoch', 'localtime') d, COUNT(*) c FROM events "
        "WHERE timestamp >= ? GROUP BY d ORDER BY d",
        (cutoff,),
    ).fetchall()
    print(f"=== Events per day, last {days} day(s) ===\n")
    if not rows:
        print("  No events in this window.")
        return
    max_c = max(c for _, c in rows)
    for d, c in rows:
        bar_len = max(1, round(c / max_c * 40)) if max_c else 0
        print(f"  {d}  {'█' * bar_len} {c}")


def main():
    parser = argparse.ArgumentParser(description="Query the event bus's durable SQLite history.")
    parser.add_argument("--summary", action="store_true", help="Overall counts by severity and source")
    parser.add_argument("--top-techniques", type=int, metavar="N", help="Most frequent technique IDs")
    parser.add_argument("--since-days", type=int, metavar="DAYS", help="All events in the last N days")
    parser.add_argument("--technique", metavar="TECHNIQUE_ID", help="All events for one technique")
    parser.add_argument("--trend", type=int, metavar="DAYS", help="Events per day, last N days, as a bar chart")
    args = parser.parse_args()

    if not any([args.summary, args.top_techniques, args.since_days, args.technique, args.trend]):
        parser.error("pass at least one of --summary, --top-techniques N, --since-days N, "
                      "--technique ID, --trend N")

    conn = connect()
    if args.summary:
        cmd_summary(conn)
    if args.top_techniques:
        cmd_top_techniques(conn, args.top_techniques)
    if args.since_days:
        cmd_since_days(conn, args.since_days)
    if args.technique:
        cmd_technique(conn, args.technique)
    if args.trend:
        cmd_trend(conn, args.trend)
    conn.close()


if __name__ == "__main__":
    main()
