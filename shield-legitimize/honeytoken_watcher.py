#!/usr/bin/env python
"""
Honeytoken watcher — MITRE Shield Legitimize tactic (DTE0013 — deploying
a decoy that looks real enough to attract interaction, then alerting on it).

Creates a decoy file that looks like a real credential dump, then watches
for NEWLY-spawned processes and checks whether any of them open it —
reusing the exact efficient pattern discovered while fixing
credential-access/credential_access_demo.py: check specific/new PIDs
directly rather than a full psutil.process_iter() scan (measured at ~12.7s
per pass across ~300 processes — far too slow to catch a short file access).
Same diff-new-processes technique as shield-detect/process_monitor.py,
applied here to file access instead of process names.

A honeytoken has exactly one legitimate reader: nobody. Any access at all
is the alert, unlike every other detector in this project which has to
separate signal from noise — this one has no noise by design.

Usage:
    python honeytoken_watcher.py --self-test
"""
import subprocess
import sys
import time
from pathlib import Path

import psutil

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

SCRATCH_DIR = Path(__file__).resolve().parent / "scratch"
HONEYTOKEN = SCRATCH_DIR / "aws_backup_credentials.txt"

DECOY_CONTENT = (
    "# AWS backup credentials - DO NOT SHARE\n"
    "AWS_ACCESS_KEY_ID=AKIA0000000000000000\n"
    "AWS_SECRET_ACCESS_KEY=0000000000000000000000000000000000FAKE\n"
)


def deploy_honeytoken():
    print("=== Deploying honeytoken (decoy credential file) ===")
    SCRATCH_DIR.mkdir(exist_ok=True)
    HONEYTOKEN.write_text(DECOY_CONTENT)
    print(f"  Deployed: {HONEYTOKEN}")


def watch_for_access(duration, known_pids):
    """Only checks PIDs that are NEW since `known_pids` - the same
    diff-based efficiency fix used in credential_access_demo.py, so this
    scales fine even though a full-system scan would not."""
    end = time.time() + duration
    caught = False
    while time.time() < end and not caught:
        current = {p.pid for p in psutil.process_iter()}
        new_pids = current - known_pids
        for pid in new_pids:
            try:
                p = psutil.Process(pid)
                for f in p.open_files():
                    if Path(f.path).resolve() == HONEYTOKEN:
                        msg = f"PID {pid} ({p.name()}) accessed the honeytoken — no legitimate reason for ANY process to open this file"
                        print(f"  ⚠️  CRITICAL: {msg}")
                        emit(source="honeytoken_watcher", technique_id="DTE0013", severity="HIGH", message=msg)
                        caught = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        known_pids = current
        if not caught:
            time.sleep(0.1)
    return caught


def self_test():
    deploy_honeytoken()
    print("\n=== Watching for access (self-test: spawns a process that reads it) ===")
    known_pids = {p.pid for p in psutil.process_iter()}

    script = (
        "import time\n"
        # bound to a variable and held open across the sleep - an unbound
        # open(...).read() gets garbage-collected (closing the handle)
        # almost immediately, before any poller could observe it
        f'f = open(r"{HONEYTOKEN}")\n'
        "data = f.read()\n"
        "time.sleep(3)\n"
        "f.close()\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", script])
    caught = watch_for_access(duration=6, known_pids=known_pids)
    proc.wait()

    cleanup()
    print(f"\n{'Self-test PASSED' if caught else 'Self-test FAILED'}.")


def cleanup():
    print("\n=== Cleanup ===")
    if HONEYTOKEN.exists():
        HONEYTOKEN.unlink()
    if SCRATCH_DIR.exists():
        SCRATCH_DIR.rmdir()
    print("  Honeytoken removed.")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        print("Usage: python honeytoken_watcher.py --self-test")
