#!/usr/bin/env python
"""
Baseline-and-deviate detection — depth roadmap, item 1. Every fixed-rule
detector in this project (process_monitor.py's LOLBin list,
lan_attack_surface.py's port list) flags KNOWN-bad patterns. This takes a
different, complementary approach: learn what's actually NORMAL for THIS
specific machine across repeated real observations, persisted durably in
SQLite (baseline-detection/baseline.db — same durability discipline as
event-bus/events.db), then flag anything that doesn't match that learned
baseline. Genuinely statistically grounded, not a hardcoded list, and able
to catch something that looks completely legitimate on its own but has
simply never run on this machine before — the exact class of thing a fixed
heuristic list can never cover because it doesn't know this machine.

Two axes, both observed in one pass over psutil.process_iter() + each
process's own net_connections() — the same per-process pattern already
proven to work unprivileged in credential_access_demo.py and
process_monitor.py, rather than the top-level psutil.net_connections()
call, which needs elevation for a system-wide view on Windows:

  - Process identity: (name, exe path) pairs seen running
  - Listening ports: which ports this machine has ever exposed a listener on

--learn folds ONE real snapshot into the accumulated baseline (increments
an observation count per item, doesn't just record "seen" once) — the
point of "across repeated runs" is that one observation could be a fluke,
but something seen 20 times over a week is genuinely this machine's normal.

--check takes a fresh snapshot and flags anything with zero prior
observations as NEW (the actual anomaly signal), and anything below a
small trust threshold as still-establishing-trust.

Usage:
    python baseline_monitor.py --learn     # fold current real state into
                                              the baseline
    python baseline_monitor.py --check     # compare current state against
                                              the baseline
    python baseline_monitor.py --self-test  # learns from real ambient
                                               state, spawns a genuinely
                                               novel process + listening
                                               socket, proves --check flags
                                               both, cleans up
"""
import shutil
import socket
import subprocess
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

import psutil

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

DB_PATH = Path(__file__).resolve().parent / "baseline.db"
LOW_TRUST_THRESHOLD = 3  # fewer than this many observations = "still establishing trust"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS process_baseline (
            exe_path TEXT PRIMARY KEY,
            name TEXT,
            first_seen REAL,
            last_seen REAL,
            observation_count INTEGER
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS port_baseline (
            port INTEGER PRIMARY KEY,
            first_seen REAL,
            last_seen REAL,
            observation_count INTEGER
        )
    """)
    conn.commit()
    return conn


def snapshot():
    """One pass: (name, exe) identity pairs, plus any LISTEN-state ports
    found on any process this session can see. Best-effort — AccessDenied
    on system processes is skipped, same pattern used elsewhere in this
    project (credential_access_demo.py, process_monitor.py)."""
    processes = set()
    listening_ports = set()
    for p in psutil.process_iter(["name", "exe"]):
        try:
            name = p.info["name"] or ""
            exe = p.info["exe"] or ""
            if exe:
                processes.add((name, exe))
            for c in p.net_connections(kind="inet"):
                if c.status == psutil.CONN_LISTEN and c.laddr:
                    listening_ports.add(c.laddr.port)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return processes, listening_ports


def learn(conn):
    processes, ports = snapshot()
    now = time.time()

    for name, exe in processes:
        conn.execute("""
            INSERT INTO process_baseline (exe_path, name, first_seen, last_seen, observation_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(exe_path) DO UPDATE SET
                last_seen = excluded.last_seen,
                observation_count = observation_count + 1
        """, (exe, name, now, now))

    for port in ports:
        conn.execute("""
            INSERT INTO port_baseline (port, first_seen, last_seen, observation_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(port) DO UPDATE SET
                last_seen = excluded.last_seen,
                observation_count = observation_count + 1
        """, (port, now, now))

    conn.commit()
    print(f"Learned from {len(processes)} process(es) and {len(ports)} listening port(s) "
          f"in this snapshot — folded into the accumulated baseline.")


def check(conn):
    """Prints MEDIUM/HIGH findings inline — those are the actual signal.
    Everything below the trust threshold is summarized as a COUNT, not one
    line per item: with only a handful of --learn passes almost the entire
    baseline legitimately hasn't cleared the threshold yet, and printing
    all of it (100+ lines on a real desktop) buries the two things that
    actually matter under noise that looks alarming but isn't. Real usage
    accumulates trust over days of --learn runs; this only affects how a
    still-young baseline reports, not the detection logic itself."""
    processes, ports = snapshot()
    findings = []
    low_trust_count = 0

    for name, exe in processes:
        row = conn.execute("SELECT observation_count FROM process_baseline WHERE exe_path=?", (exe,)).fetchone()
        if row is None:
            msg = f"Process never seen before on this machine: {name} ({exe})"
            print(f"  ⚠️  MEDIUM: {msg}")
            findings.append(("MEDIUM", msg))
            emit(source="baseline_monitor", technique_id="DTE0007", severity="MEDIUM", message=msg)
        elif row[0] < LOW_TRUST_THRESHOLD:
            low_trust_count += 1

    for port in ports:
        row = conn.execute("SELECT observation_count FROM port_baseline WHERE port=?", (port,)).fetchone()
        if row is None:
            msg = f"New listening port never seen before: {port}"
            print(f"  ⚠️  HIGH: {msg}")
            findings.append(("HIGH", msg))
            emit(source="baseline_monitor", technique_id="DTE0007", severity="HIGH", message=msg)
        elif row[0] < LOW_TRUST_THRESHOLD:
            low_trust_count += 1

    if not findings:
        print("  Nothing outside the learned baseline.")
    if low_trust_count:
        print(f"  ({low_trust_count} item(s) still establishing trust — fewer than "
              f"{LOW_TRUST_THRESHOLD} observations, not flagged individually)")
    return findings


def self_test():
    print("=== Baseline-and-deviate self-test ===\n")
    conn = init_db()

    print("--- Learning from real ambient state (this machine, right now) ---")
    learn(conn)
    learn(conn)  # a second real observation — proves observation_count actually accumulates
    row = conn.execute("SELECT observation_count FROM process_baseline ORDER BY observation_count DESC LIMIT 1").fetchone()
    print(f"  (highest observation_count in the baseline after 2 learns: {row[0] if row else 0})\n")

    print("--- Introducing two genuinely novel things ---")
    tmp_dir = Path(tempfile.mkdtemp(prefix="pycyber_baseline_"))
    fake_exe = tmp_dir / "totally_normal_tool.exe"
    shutil.copy(sys.executable, fake_exe)
    proc = subprocess.Popen([str(fake_exe), "-c", "import time; time.sleep(4)"])
    print(f"  Spawned a never-before-run executable: {fake_exe}")

    demo_port = 54329
    demo_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    demo_socket.bind(("127.0.0.1", demo_port))
    demo_socket.listen(1)
    print(f"  Opened a never-before-seen listening port: {demo_port}")

    time.sleep(0.5)
    print("\n--- Checking current state against the learned baseline ---")
    findings = check(conn)

    caught_process = any(str(fake_exe) in msg for _, msg in findings)
    caught_port = any(str(demo_port) in msg for _, msg in findings)

    demo_socket.close()
    proc.terminate()
    proc.wait(timeout=5)
    shutil.rmtree(tmp_dir, ignore_errors=True)
    conn.close()

    passed = caught_process and caught_port
    print(f"\n{'Self-test PASSED' if passed else 'Self-test FAILED'} — "
          f"novel process {'caught' if caught_process else 'MISSED'}, "
          f"novel port {'caught' if caught_port else 'MISSED'}. "
          f"Cleaned up; the real ambient baseline learned above is kept.")


def main():
    args = sys.argv[1:]
    if "--self-test" in args:
        self_test()
        return
    conn = init_db()
    if "--learn" in args:
        learn(conn)
    elif "--check" in args:
        print("=== Checking current state against the learned baseline ===\n")
        check(conn)
    else:
        print("Usage: python baseline_monitor.py [--learn | --check | --self-test]")
    conn.close()


if __name__ == "__main__":
    main()
