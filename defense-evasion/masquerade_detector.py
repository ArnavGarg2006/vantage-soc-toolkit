#!/usr/bin/env python
"""
Masquerading detector — MITRE ATT&CK Defense Evasion tactic
(T1036.005 Match Legitimate Name or Location)

Detects processes named after well-known Windows system binaries but
running from a location those binaries never legitimately run from — a
classic malware trick: name your payload "svchost.exe" hoping a human (or a
naive rule matching on process name alone) won't look at the actual path.

Purely observational — never kills or blocks anything, and never touches
any file. Self-test spawns Python renamed to look like a system binary name
via the process's own display, proving the path-mismatch check actually
fires, not just that the expected-paths table exists.

Usage:
    python masquerade_detector.py
    python masquerade_detector.py --self-test
"""
import shutil
import sys
import tempfile
from pathlib import Path

import psutil

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

# name (lowercase) -> directories it's legitimately allowed to run from
EXPECTED_LOCATIONS = {
    "svchost.exe": [r"c:\windows\system32", r"c:\windows\syswow64"],
    "explorer.exe": [r"c:\windows"],
    "csrss.exe": [r"c:\windows\system32"],
    "winlogon.exe": [r"c:\windows\system32"],
    "lsass.exe": [r"c:\windows\system32"],
    "services.exe": [r"c:\windows\system32"],
    "smss.exe": [r"c:\windows\system32"],
    "wininit.exe": [r"c:\windows\system32"],
    "spoolsv.exe": [r"c:\windows\system32"],
    "taskhostw.exe": [r"c:\windows\system32"],
    "dwm.exe": [r"c:\windows\system32"],
}


def scan():
    print("=== Masquerade scan — process name vs. expected location ===\n")
    findings = []
    for p in psutil.process_iter(["pid", "name", "exe"]):
        name = (p.info["name"] or "").lower()
        exe = (p.info["exe"] or "").lower()
        if name not in EXPECTED_LOCATIONS or not exe:
            continue
        allowed = EXPECTED_LOCATIONS[name]
        if not any(exe.startswith(loc) for loc in allowed):
            findings.append((p.info["pid"], p.info["name"], p.info["exe"]))
            msg = f"PID {p.info['pid']} named '{p.info['name']}' running from '{p.info['exe']}' — not one of {allowed}"
            print(f"  ⚠️  HIGH: {msg}")
            emit(source="masquerade_detector", technique_id="T1036.005", severity="HIGH", message=msg)

    if not findings:
        print("  No masquerading processes detected — every matched name is running from its expected location.")
    return findings


def self_test():
    """Copies the Python interpreter itself to a temp dir under the name
    'svchost.exe' and launches it — a real process, really named like a
    system binary, really running from the wrong place. Proves the
    path-mismatch logic actually fires against a live process, not just
    that the EXPECTED_LOCATIONS table looks right on paper. Cleaned up
    immediately after."""
    print("Self-test: launching a renamed copy of python.exe as 'svchost.exe' from %TEMP%...\n")
    tmp_dir = Path(tempfile.mkdtemp(prefix="pycyber_masq_"))
    fake_path = tmp_dir / "svchost.exe"
    shutil.copy(sys.executable, fake_path)

    import subprocess
    proc = subprocess.Popen([str(fake_path), "-c", "import time; time.sleep(3)"])
    import time
    time.sleep(0.5)

    findings = scan()
    found_it = any(f[0] == proc.pid for f in findings)

    proc.terminate()
    proc.wait(timeout=5)
    shutil.rmtree(tmp_dir, ignore_errors=True)

    print(f"\n{'Self-test PASSED' if found_it else 'Self-test FAILED'} — "
          f"{'correctly flagged' if found_it else 'did NOT flag'} the fake svchost.exe. Cleaned up temp copy.")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        scan()
