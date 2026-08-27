#!/usr/bin/env python
"""
Contain & Disrupt — MITRE Shield tactics (DTE0011 Contain, DTE0021 Disrupt)

The natural next step after Detect: given something flagged as suspicious,
what does a safe response actually look like? Two response types, both
demonstrated only against things this script controls:

  Process containment/disruption — spawns its own benign "suspicious-looking"
  process (never touches a real user process), then:
    - CONTAIN: suspend it (psutil) — reversible, the process is paused, not
      killed. Verified via psutil status, then resumed to prove reversibility.
    - DISRUPT: terminate it — only ever the process this script itself spawned.

  Network disruption — adds a Windows Firewall rule blocking outbound traffic
  to a documentation-only IP range (203.0.113.0/24, RFC 5737 TEST-NET-3 —
  reserved specifically for examples, nothing real is ever reachable there),
  verifies the rule exists, then removes it. Needs an elevated terminal.

Usage:
    python contain_disrupt_demo.py --process   # suspend/resume/terminate demo
    python contain_disrupt_demo.py --network    # firewall block demo (needs admin)
    python contain_disrupt_demo.py --all
"""
import subprocess
import sys
import time

import psutil

sys.stdout.reconfigure(encoding="utf-8")

FIREWALL_RULE_NAME = "PyCyberDemo_ContainDisrupt_TESTNET_Block"
TEST_NET_CIDR = "203.0.113.0/24"  # RFC 5737 TEST-NET-3 - reserved for documentation, never real


def process_contain_disrupt_demo():
    print("=== Process containment & disruption demo ===")
    print("Spawning a benign demo process (a sleep loop) — never a real user process...")
    proc = subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-Command", "while ($true) { Start-Sleep -Seconds 1 }"],
    )
    time.sleep(0.5)
    p = psutil.Process(proc.pid)
    print(f"  Spawned PID {proc.pid}, status: {p.status()}")

    print("\n--- CONTAIN: suspending ---")
    p.suspend()
    time.sleep(0.3)
    print(f"  Status after suspend: {p.status()}")
    if p.status() == psutil.STATUS_STOPPED:
        print("  ✓ Contained — process is paused, still exists, did no further work while suspended.")

    print("\n--- Resuming (proving containment is reversible) ---")
    p.resume()
    time.sleep(0.3)
    print(f"  Status after resume: {p.status()}")

    print("\n--- DISRUPT: terminating ---")
    p.terminate()
    try:
        p.wait(timeout=3)
        print(f"  Process {proc.pid} terminated.")
    except psutil.TimeoutExpired:
        p.kill()
        print(f"  Process {proc.pid} force-killed after terminate timeout.")


def run_netsh(args):
    result = subprocess.run(["netsh", *args], capture_output=True, text=True, timeout=15)
    return result.returncode, result.stdout, result.stderr


def network_disrupt_demo():
    print("\n=== Network disruption demo (Windows Firewall) ===")
    print(f"  Blocking outbound to {TEST_NET_CIDR} (RFC 5737 documentation range — never a real host)")

    rc, out, err = run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={FIREWALL_RULE_NAME}", "dir=out", "action=block",
        f"remoteip={TEST_NET_CIDR}", "enable=yes",
    ])
    if rc != 0:
        print(f"  Failed to add rule (needs an elevated/administrator terminal): {err or out}")
        return

    print("  Rule added. Verifying...")
    rc, out, _ = run_netsh(["advfirewall", "firewall", "show", "rule", f"name={FIREWALL_RULE_NAME}"])
    if FIREWALL_RULE_NAME in out:
        print("  ✓ Verified: rule exists in the firewall.")
    else:
        print("  Could not verify rule presence.")

    print("\n  Removing rule (cleanup)...")
    rc, out, err = run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={FIREWALL_RULE_NAME}"])
    print("  Removed." if rc == 0 else f"  Cleanup failed: {err or out}")


def main():
    args = sys.argv[1:]
    if "--all" in args or "--process" in args:
        process_contain_disrupt_demo()
    if "--all" in args or "--network" in args:
        network_disrupt_demo()
    if not args:
        print("Usage: python contain_disrupt_demo.py [--process] [--network] [--all]")


if __name__ == "__main__":
    main()
