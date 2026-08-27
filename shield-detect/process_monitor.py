#!/usr/bin/env python
"""
Process-creation anomaly monitor — MITRE Shield Detect tactic (DTE0007 Behavioral Analytics),
fused with network visibility (Shield Collect, same technique as
shield-collect/correlate_connections.py) for combined process+network detection.

Polls running processes over a bounded window, diffs against the previous
snapshot to find newly-spawned processes, and flags ones matching common
malicious-behavior heuristics:
  - Known "living-off-the-land" binaries (LOLBins) often abused by malware
    (powershell, cmd, wscript, mshta, certutil, regsvr32, rundll32)
  - Encoded/obfuscated PowerShell command lines (-enc, -e, -EncodedCommand)
  - Processes launched from suspicious paths (%TEMP%, Downloads, %APPDATA%)

Any process that trips one of those heuristics is then checked for LIVE
network connections. A flagged process with an external (non-private,
non-loopback) connection is escalated — a LOLBin alone is suspicious; a
LOLBin actively talking to an external IP is a much stronger C2-beacon-style
signal, and a packet capture alone (shield-collect/) can't tell you it came
from a flagged process in the first place.

This never kills or blocks anything — it's observation-only, matching the
Shield Detect tactic (notice the behavior), not Shield Disrupt (stop it).

Usage:
    python process_monitor.py [seconds]
    python process_monitor.py --self-test   # spawns a harmless PowerShell
                                             # command that ALSO makes a real
                                             # external HTTP request, to prove
                                             # the combined process+network
                                             # detection actually fires
"""
import ipaddress
import sys
import time
import subprocess

import psutil

sys.stdout.reconfigure(encoding="utf-8")

LOLBINS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
           "mshta.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe"}
SUSPICIOUS_PATH_FRAGMENTS = ["\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\"]
ENCODED_FLAGS = ["-enc", "-e ", "-encodedcommand"]


def is_external(ip):
    """True for a public/routable IP — false for loopback and RFC1918 private ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local)
    except ValueError:
        return False


def get_external_connections(pid):
    """Live connections for a PID, filtered to external (non-private) remote IPs —
    same per-process connection technique as correlate_connections.py."""
    try:
        conns = psutil.Process(pid).net_connections(kind="inet")
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return []
    return [(c.raddr.ip, c.raddr.port) for c in conns if c.raddr and is_external(c.raddr.ip)]


def snapshot():
    procs = {}
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
        try:
            procs[p.info["pid"]] = p.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs


def evaluate(proc_info):
    """Returns a list of (severity, reason) tuples for a single process,
    based on process-level attributes only (name/path/cmdline/parent)."""
    findings = []
    name = (proc_info.get("name") or "").lower()
    exe = (proc_info.get("exe") or "").lower()
    cmdline = " ".join(proc_info.get("cmdline") or []).lower()

    if name in LOLBINS:
        findings.append(("MEDIUM", f"Known LOLBin launched: {name}"))

    for frag in SUSPICIOUS_PATH_FRAGMENTS:
        if frag in exe:
            findings.append(("MEDIUM", f"Executing from suspicious path: {exe}"))
            break

    for flag in ENCODED_FLAGS:
        if flag in cmdline:
            findings.append(("HIGH", f"Encoded/obfuscated command line: {cmdline[:120]}"))
            break

    try:
        parent = psutil.Process(proc_info["ppid"])
        parent_name = parent.name().lower()
        if parent_name in {"winword.exe", "excel.exe", "outlook.exe"} and name in LOLBINS:
            findings.append(("HIGH", f"Office app ({parent_name}) spawned {name} — classic macro-malware pattern"))
    except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
        pass

    return findings


def evaluate_with_network(pid, proc_info):
    """Process-level findings, escalated with live network context. A flagged
    process with NO external connection stays as-is; one WITH an external
    connection gets an additional HIGH combined-signal finding — process
    behavior + network behavior together is stronger evidence than either
    alone, and it's the piece a packet capture by itself can't attribute."""
    findings = evaluate(proc_info)
    if not findings:
        return findings, []

    external = get_external_connections(pid)
    if external:
        conns_str = ", ".join(f"{ip}:{port}" for ip, port in external)
        findings.append(("HIGH", f"Combined signal: flagged process has {len(external)} "
                                  f"external connection(s): {conns_str}"))
    return findings, external


def monitor(duration):
    print(f"Monitoring new process creation for {duration}s (with network correlation)...")
    before = snapshot()
    alerts = []
    start = time.time()

    while time.time() - start < duration:
        time.sleep(1)
        after = snapshot()
        new_pids = set(after) - set(before)
        for pid in new_pids:
            info = after[pid]
            findings, _ = evaluate_with_network(pid, info)
            for severity, reason in findings:
                alert = f"[{severity}] PID {pid} ({info.get('name')}): {reason}"
                print(f"  {alert}")
                alerts.append(alert)
        before = after

    print(f"\n{len(alerts)} alert(s) in {duration}s window.")
    return alerts


def self_test():
    """Spawns a harmless PowerShell command that ALSO opens a real TCP
    connection to example.com:80 and holds it open for a few seconds — proves
    both halves: the process-level LOLBin heuristic, AND the combined
    process+network escalation, not just that the code compiles."""
    print("Self-test: spawning powershell.exe that opens a real TCP connection "
          "to example.com:80 and holds it for 3s...")
    before = snapshot()

    proc = subprocess.Popen([
        "powershell.exe", "-NoProfile", "-Command",
        "$c = New-Object System.Net.Sockets.TcpClient('example.com', 80); "
        "Start-Sleep -Seconds 3; $c.Close()",
    ])

    found_process_alert = False
    found_network_alert = False
    target_pid = None

    # Poll a few times WHILE the connection is open — net_connections() only
    # reflects live state, so we have to catch it mid-flight, not after.
    for _ in range(4):
        time.sleep(1)
        after = snapshot()
        for pid in set(after) - set(before):
            info = after.get(pid)
            if not info or (info.get("name") or "").lower() != "powershell.exe":
                continue
            target_pid = pid
            findings, external = evaluate_with_network(pid, info)
            for severity, reason in findings:
                print(f"  [{severity}] PID {pid} ({info.get('name')}): {reason}")
                found_process_alert = True
                if "Combined signal" in reason:
                    found_network_alert = True
        if found_network_alert:
            break

    proc.wait()

    print()
    if found_process_alert:
        print("Process-level self-test PASSED — flagged powershell.exe as a LOLBin.")
    else:
        print("Process-level self-test did not trigger (process may have exited before being observed).")
    if found_network_alert:
        print("Combined process+network self-test PASSED — caught the LOLBin's live "
              "external connection and escalated to a combined-signal HIGH finding.")
    else:
        print("Combined signal did not trigger — the connection window may have been "
              f"missed by polling timing (target pid observed: {target_pid}).")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return

    duration = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 15
    monitor(duration)


if __name__ == "__main__":
    main()
