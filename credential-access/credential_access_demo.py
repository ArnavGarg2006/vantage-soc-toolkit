#!/usr/bin/env python
"""
Credential Access — MITRE ATT&CK Credential Access tactic (T1555.003
Credentials from Password Stores: Credentials from Web Browsers)
paired with a real defensive check on actual browser credential stores.

The "attack" side never touches your real saved passwords. It creates its
OWN throwaway SQLite file, styled after (not copied from) the structure
browsers use, populated only with obviously-fake test data, then
demonstrates the technique attackers actually use: querying a structured
local credential store. That's the entire technique — no real decryption
of anything, because there's nothing real to decrypt here.

The "defense" side is real: it checks whether YOUR actual Chrome/Edge
"Login Data" file exists and which processes currently hold it open — the
same technique EDR products use to catch a process reading it that isn't
the browser itself. Read-only, reports paths and process names only, never
opens or reads the real file's contents.

Usage:
    python credential_access_demo.py --demo   # dummy store, create + harvest
    python credential_access_demo.py --hunt   # check real browser stores
"""
import argparse
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import psutil

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

# .resolve() matters: __file__ can be relative depending on how the script is
# invoked, but psutil.open_files() always returns absolute paths - comparing
# a possibly-relative DUMMY_DB against that silently never matches.
SCRATCH_DIR = Path(__file__).resolve().parent / "scratch"
DUMMY_DB = SCRATCH_DIR / "test_credentials.db"

FAKE_ENTRIES = [
    ("https://demo-bank.test", "test.user@example.com", "fake-password-123-NOT-REAL"),
    ("https://demo-mail.test", "demo.account@example.com", "fake-password-456-NOT-REAL"),
    ("https://demo-shop.test", "shopper.test@example.com", "fake-password-789-NOT-REAL"),
]

REAL_BROWSER_STORE_PATHS = {
    "Chrome": Path(os.environ.get("LOCALAPPDATA", "")) / r"Google\Chrome\User Data\Default\Login Data",
    "Edge": Path(os.environ.get("LOCALAPPDATA", "")) / r"Microsoft\Edge\User Data\Default\Login Data",
}


def create_dummy_store():
    print("=== Creating dummy credential store (fake data only) ===")
    SCRATCH_DIR.mkdir(exist_ok=True)
    if DUMMY_DB.exists():
        DUMMY_DB.unlink()

    conn = sqlite3.connect(DUMMY_DB)
    conn.execute("CREATE TABLE logins (origin_url TEXT, username TEXT, password TEXT)")
    conn.executemany("INSERT INTO logins VALUES (?, ?, ?)", FAKE_ENTRIES)
    conn.commit()
    conn.close()
    print(f"  Created {DUMMY_DB} with {len(FAKE_ENTRIES)} fake entries.")


def harvest_dummy_store():
    """This is the technique: querying a structured local credential store.
    Real malware does exactly this against the real file — the only
    difference here is the file, and everything in it, is ours."""
    print("\n=== Harvesting dummy store (the technique, on fake data) ===")
    if not DUMMY_DB.exists():
        print("  No dummy store found — run with --demo first.")
        return
    conn = sqlite3.connect(DUMMY_DB)
    rows = conn.execute("SELECT origin_url, username, password FROM logins").fetchall()
    conn.close()
    for url, user, pw in rows:
        print(f"  {url:25} {user:30} {pw}")
    print(f"\n  ({len(rows)} fake credential(s) — never real, never your data)")


def harvest_dummy_store_subprocess():
    """Closes the detection gap the scorecard found: harvest_dummy_store()
    reads the file in the SAME process that created it, which a real
    detector correctly should not flag (a process reading its own data is
    normal). Real credential theft is a DIFFERENT process reading a store
    someone else created — malware reading the browser's file, not the
    browser reading its own. This spawns a genuinely separate process to do
    the harvesting, so the cross-process detection in watch_dummy_store()
    below has something real to catch."""
    print("\n=== Harvesting dummy store from a SEPARATE process (the realistic technique) ===")
    if not DUMMY_DB.exists():
        print("  No dummy store found — run with --demo first.")
        return None
    script = (
        "import sqlite3, time\n"
        f'conn = sqlite3.connect(r"{DUMMY_DB}")\n'
        "rows = conn.execute('SELECT origin_url, username, password FROM logins').fetchall()\n"
        "time.sleep(5)\n"  # generous margin: child interpreter startup latency can eat 1-2s
        "conn.close()\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", script])
    print(f"  Spawned separate PID {proc.pid} to do the harvesting.")
    return proc


def watch_dummy_store(duration=5, target_pid=None):
    """The same open_files() cross-process check hunt_credential_access()
    uses for real browser stores, generalized to also watch the dummy store.

    target_pid matters a lot here, and the reason why is itself worth
    documenting: a full psutil.process_iter() + open_files() pass across
    every process on this machine measured at ~12.7s for ~300 processes —
    slower than the whole demo's watch window, so blind full-system polling
    literally cannot catch a file held open for only a few seconds. This
    isn't a bug to paper over with a longer sleep; it's the real reason
    production EDR tools use kernel-level file-system minifilter drivers or
    ETW instead of user-mode polling. The realistic, honest fix: check the
    SPECIFIC pid you already have a reason to be suspicious of — exactly the
    workflow process_monitor.py already sets up (flag a PID, then check what
    THAT PID has open), not "scan the whole system every 150ms."
    """
    label = f"PID {target_pid}" if target_pid else "all processes (slow - see docstring)"
    print(f"\n=== Watching dummy store for cross-process access ({duration}s window, {label}) ===")
    my_pid = os.getpid()
    caught = False
    end = time.time() + duration

    def check_process(p):
        nonlocal caught
        try:
            for f in p.open_files():
                if Path(f.path).resolve() == DUMMY_DB:
                    msg = f"PID {p.pid} ({p.name()}) has the credential store open and is not the process that created it."
                    print(f"  ⚠️  HIGH: {msg}")
                    emit(source="credential_access_demo", technique_id="T1555.003", severity="HIGH", message=msg)
                    caught = True
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass

    while time.time() < end and not caught:
        if target_pid:
            try:
                check_process(psutil.Process(target_pid))
            except psutil.NoSuchProcess:
                pass
        else:
            for p in psutil.process_iter(["pid"]):
                if p.info["pid"] == my_pid:
                    continue
                check_process(p)
        if not caught:
            time.sleep(0.1)

    if not caught:
        print("  No cross-process access observed in this window.")
    return caught


def hunt_credential_access():
    """Defensive: report whether real browser credential stores exist and
    which processes currently hold them open. Never reads their contents."""
    print("=== Credential-store access hunter (defensive, read-only) ===\n")

    for browser, path in REAL_BROWSER_STORE_PATHS.items():
        exists = path.exists()
        print(f"{browser} Login Data: {'found' if exists else 'not found'} at {path}")
        if not exists:
            continue

        holders = []
        for p in psutil.process_iter(["pid", "name"]):
            try:
                for f in p.open_files():
                    if Path(f.path).resolve() == path:
                        holders.append((p.info["pid"], p.info["name"]))
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

        if not holders:
            print("  No process currently has it open.")
        else:
            for pid, name in holders:
                is_browser = browser.lower() in name.lower()
                flag = "" if is_browser else "  ⚠️  NOT the browser itself"
                print(f"  Open by PID {pid} ({name}){flag}")
                if not is_browser:
                    emit(source="credential_access_demo", technique_id="T1555.003", severity="HIGH",
                         message=f"PID {pid} ({name}) holds {browser}'s real Login Data open and is not the browser")
        print()


def main():
    parser = argparse.ArgumentParser(description="Credential Access technique demo + real credential-store hunter.")
    parser.add_argument("--demo", action="store_true", help="Create and harvest the dummy credential store (same-process)")
    parser.add_argument("--demo-realistic", action="store_true",
                         help="Create store, harvest from a SEPARATE process while watching for it (closes the detection gap)")
    parser.add_argument("--hunt", action="store_true", help="Check real browser credential stores (defensive)")
    args = parser.parse_args()

    if not (args.demo or args.demo_realistic or args.hunt):
        parser.error("pass --demo, --demo-realistic, or --hunt")

    if args.demo:
        create_dummy_store()
        harvest_dummy_store()
    if args.demo_realistic:
        create_dummy_store()
        proc = harvest_dummy_store_subprocess()
        if proc:
            watch_dummy_store(duration=6, target_pid=proc.pid)
            proc.wait()
    if args.hunt:
        hunt_credential_access()


if __name__ == "__main__":
    main()
