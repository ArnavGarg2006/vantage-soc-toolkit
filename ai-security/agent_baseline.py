#!/usr/bin/env python
"""
Agent tool-call baseline — the exact same methodology as
baseline-detection/baseline_monitor.py (learn what's normal across
repeated real observations, flag deviations, persist durably in SQLite),
applied to a different kind of data: the sequence of tool/function calls
an AI agent makes, instead of OS processes and listening ports. This is
the direct answer to "how does this project's approach make AI systems
more robust" — the detection methodology transfers essentially unchanged;
only the thing being observed changes.

Honest scope note, stated plainly rather than implied: this project has
no live AI agent framework integrated to hook into, so there's no real
production tool-call telemetry to learn from the way baseline_monitor.py
learns from this machine's actual real processes. What's demonstrated and
verified here is the DETECTION LOGIC itself — the same bigram-transition
baselining approach a real integration would use — against realistic,
hand-authored sample tool-call sequences representing common agent
workflows. That's a real, verified capability (the logic is genuinely
correct, checked below), just not yet wired to a live agent's actual
telemetry stream. A real integration point: any agent framework that logs
each tool call as (agent_id, tool_name, timestamp) could feed --learn
directly.

Baselines bigram transitions (tool_A -> tool_B) rather than whole
sequences, so a NEW tool sequence built entirely from previously-seen
transitions doesn't false-positive, but a transition that's never
happened before does — the same "have I seen this specific pair before"
logic as baseline_monitor.py's process/port checks, just applied to
consecutive tool calls instead of consecutive observations.

Usage:
    python agent_baseline.py --learn      # fold sample "normal" agent
                                             workflows into the baseline
    python agent_baseline.py --check <tool1> <tool2> ...
                                           # check one tool-call sequence
    python agent_baseline.py --self-test  # learns from realistic normal
                                             workflows, then checks a
                                             sequence containing a genuine
                                             never-seen transition,
                                             proves it's flagged
"""
import sqlite3
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402

DB_PATH = Path(__file__).resolve().parent / "agent_baseline.db"

# Realistic sample "normal" agent workflows — the kind of tool sequences a
# coding assistant or research agent genuinely produces. Not live
# telemetry (see module docstring); representative sample data standing
# in for it.
NORMAL_WORKFLOWS = [
    ["search_web", "read_page", "summarize"],
    ["read_file", "edit_file", "run_tests"],
    ["read_file", "read_file", "edit_file", "run_tests"],
    ["search_web", "read_page", "read_page", "summarize"],
    ["list_directory", "read_file", "edit_file"],
    ["run_tests", "read_file", "edit_file", "run_tests"],
]

# A workflow with a transition that never appears above: reading a file,
# then straight to sending an HTTP request - the exfiltration-shaped
# pattern this whole methodology exists to catch.
SUSPICIOUS_WORKFLOW = ["read_file", "read_credentials_file", "send_http_request"]


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transition_baseline (
            from_tool TEXT NOT NULL,
            to_tool TEXT NOT NULL,
            first_seen REAL,
            last_seen REAL,
            observation_count INTEGER,
            PRIMARY KEY (from_tool, to_tool)
        )
    """)
    conn.commit()
    return conn


def bigrams(sequence):
    return list(zip(sequence, sequence[1:]))


def learn(conn, workflows):
    now = time.time()
    total_transitions = 0
    for workflow in workflows:
        for a, b in bigrams(workflow):
            total_transitions += 1
            conn.execute("""
                INSERT INTO transition_baseline (from_tool, to_tool, first_seen, last_seen, observation_count)
                VALUES (?, ?, ?, ?, 1)
                ON CONFLICT(from_tool, to_tool) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    observation_count = observation_count + 1
            """, (a, b, now, now))
    conn.commit()
    print(f"Learned from {len(workflows)} workflow(s), {total_transitions} tool-call transition(s).")


def check(conn, sequence):
    print(f"=== Checking sequence: {' -> '.join(sequence)} ===")
    findings = []
    for a, b in bigrams(sequence):
        row = conn.execute(
            "SELECT observation_count FROM transition_baseline WHERE from_tool=? AND to_tool=?",
            (a, b),
        ).fetchone()
        if row is None:
            msg = f"Never-seen tool transition: {a} -> {b}"
            print(f"  ⚠️  HIGH: {msg}")
            findings.append(("HIGH", msg))
            emit(source="agent_baseline", technique_id="AML.T0053", severity="HIGH", message=msg)
        else:
            print(f"  ok: {a} -> {b} (seen {row[0]} time(s) before)")
    if not findings:
        print("  Entire sequence matches the learned baseline.")
    return findings


def self_test():
    print("=== Agent tool-call baseline self-test ===\n")
    conn = init_db()

    print("--- Learning from realistic normal agent workflows ---")
    learn(conn, NORMAL_WORKFLOWS)

    print(f"\n--- Checking a known-normal sequence (should be clean) ---")
    clean_findings = check(conn, ["read_file", "edit_file", "run_tests"])

    print(f"\n--- Checking a sequence with a genuine never-seen transition ---")
    suspicious_findings = check(conn, SUSPICIOUS_WORKFLOW)

    conn.close()
    passed = len(clean_findings) == 0 and len(suspicious_findings) > 0
    print(f"\n{'Self-test PASSED' if passed else 'Self-test FAILED'} — "
          f"known-normal sequence {'stayed clean' if not clean_findings else 'incorrectly flagged'}, "
          f"suspicious sequence {'correctly flagged' if suspicious_findings else 'MISSED'}.")


def main():
    args = sys.argv[1:]
    if "--self-test" in args:
        self_test()
        return
    conn = init_db()
    if "--learn" in args:
        learn(conn, NORMAL_WORKFLOWS)
    elif "--check" in args:
        i = args.index("--check")
        check(conn, args[i + 1:])
    else:
        print("Usage: python agent_baseline.py [--learn | --check tool1 tool2 ... | --self-test]")
    conn.close()


if __name__ == "__main__":
    main()
