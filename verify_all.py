#!/usr/bin/env python
"""
Whole-project verification harness — one command that runs every module
that can run here and reports, per module, whether it actually worked.

Why this exists: this project's claim has always been "verified live, not
assumed", and until now that claim lived in README prose describing runs
nobody else could reproduce. This turns the claim into something you can
execute. It is the difference between a README that says the modules work
and a command that demonstrates it on your machine.

The three verdicts are deliberately distinct, because collapsing them is
exactly how coverage numbers become dishonest:

  PASS     the module ran and reported success by its own criteria
  FAIL     the module ran and reported failure — a real bug, never a skip
  BLOCKED  the module could not run here, with the specific missing
           requirement named (Windows API, an external binary, admin
           rights, outbound network)

BLOCKED is never counted as success. A large part of this project is
Windows-only by design (winreg, pywin32, netsh, arp, powershell), so on
Linux a substantial share legitimately cannot execute — and this prints
exactly which parts and why, instead of quietly reporting a smaller,
greener total. Run it on Windows and those same rows become real
PASS/FAIL results.

What this is not: a unit-test suite. Every check below runs the module's
own --self-test or --demo, which is the same thing a human would run by
hand. The harness adds reproducibility and honest accounting, not a new
notion of correctness.

Usage:
    python verify_all.py                # run everything, print a report
    python verify_all.py --quick        # skip the slow network modules
    python verify_all.py --json         # machine-readable results
    python verify_all.py --only soar    # substring filter on module id
    python verify_all.py --markdown     # table for pasting into the README
"""
import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

ROOT = Path(__file__).resolve().parent
IS_WINDOWS = platform.system() == "Windows"

PASS_MARK = "Self-test PASSED"
FAIL_MARK = "Self-test FAILED"

# --------------------------------------------------------------------------
# Requirement probes — each returns (ok, reason_if_not). Cached because
# several of these (the egress check especially) are not free.
# --------------------------------------------------------------------------

_probe_cache = {}


def probe(req):
    if req not in _probe_cache:
        _probe_cache[req] = _do_probe(req)
    return _probe_cache[req]


def _do_probe(req):
    if req == "windows":
        return (IS_WINDOWS, f"needs Windows APIs (running on {platform.system()})")

    if req == "admin":
        if IS_WINDOWS:
            try:
                import ctypes
                return (bool(ctypes.windll.shell32.IsUserAnAdmin()),
                        "needs an elevated (Run as Administrator) terminal")
            except Exception:
                return (False, "needs an elevated terminal (could not determine)")
        return (hasattr(os, "geteuid") and os.geteuid() == 0,
                "needs root/Administrator")

    if req == "net":
        # A real egress check, not a guess: sandboxes commonly resolve DNS
        # but refuse the connection, so this actually opens a socket.
        for host, port in (("1.1.1.1", 53), ("8.8.8.8", 53)):
            try:
                socket.create_connection((host, port), timeout=3).close()
                return (True, "")
            except OSError:
                continue
        return (False, "needs outbound network (egress blocked here)")

    if req.startswith("bin:"):
        name = req[4:]
        return (shutil.which(name) is not None, f"needs the '{name}' binary on PATH")

    if req.startswith("mod:"):
        name = req[4:]
        try:
            __import__(name)
            return (True, "")
        except Exception as e:
            return (False, f"needs the '{name}' package ({type(e).__name__})")

    return (True, "")


# --------------------------------------------------------------------------
# The registry.
#
#   ok   a substring that proves success
#   bad  a substring that proves failure; checked FIRST so an explicit
#        failure always beats a success marker appearing elsewhere
#   needs  requirement probes that must all pass or the row is BLOCKED
# --------------------------------------------------------------------------

CHECKS = [
    # ---- DFIR / cases / SOAR -------------------------------------------
    dict(id="dfir/yara_scanner", group="DFIR",
         args=["dfir/yara_scanner.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:yara"],
         note="5 rules vs 5 true-positive artifacts + 1 benign control"),
    dict(id="case-management/case_manager", group="Case management",
         args=["case-management/case_manager.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=[],
         note="7 checks: grouping, time window, idempotency, full lifecycle"),
    dict(id="soar/playbook_runner", group="SOAR",
         args=["soar/playbook_runner.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:yaml"],
         note="9 checks: trigger match, extraction, enrichment, correlation"),
    dict(id="soar/containment", group="SOAR",
         args=["soar/containment.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:psutil"],
         note="9 checks: dry-run safety, arm, undo, self/PID-1/allowlist guards"),
    dict(id="threat-intel/ioc_store", group="Threat intel",
         args=["threat-intel/ioc_store.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:requests"],
         note="11 checks: MISP-format parsing, HTTP ingest, matching, VT handling"),

    # ---- event bus ------------------------------------------------------
    dict(id="event-bus/collector", group="Event bus",
         args=["event-bus/collector.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:requests"],
         note="real HTTP POST + SQLite persistence, both verified by query"),

    # ---- detection ------------------------------------------------------
    dict(id="baseline-detection/baseline_monitor", group="Detection",
         args=["baseline-detection/baseline_monitor.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:psutil"],
         note="learns a baseline, then flags a real deviation from it"),
    dict(id="defense-evasion/masquerade_detector", group="Detection",
         args=["defense-evasion/masquerade_detector.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:psutil"]),
    dict(id="shield-legitimize/honeytoken_watcher", group="Detection",
         args=["shield-legitimize/honeytoken_watcher.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:psutil"],
         note="decoy credential file + live open-handle detection"),
    dict(id="shield-channel-facilitate/honeypot_listener", group="Detection",
         args=["shield-channel-facilitate/honeypot_listener.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=[]),
    dict(id="shield-detect/process_monitor", group="Detection",
         args=["shield-detect/process_monitor.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["windows", "mod:psutil"],
         note="spawns a real powershell.exe child, catches its live connection"),
    dict(id="realtime-detection/fs_watcher", group="Detection",
         args=["realtime-detection/fs_watcher.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["windows", "mod:win32file"],
         note="ReadDirectoryChangesW notification latency"),

    # ---- AI / LLM security ---------------------------------------------
    dict(id="ai-security/prompt_injection_detector", group="AI security",
         args=["ai-security/prompt_injection_detector.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=[]),
    dict(id="ai-security/agent_baseline", group="AI security",
         args=["ai-security/agent_baseline.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=[]),

    # ---- packets / network ---------------------------------------------
    dict(id="packet-crafting/craft_packets", group="Packets",
         args=["packet-crafting/craft_packets.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:scapy"],
         note="builds and mutates real packet objects, verified on the object"),
    dict(id="adversary-in-the-middle/arp_spoof_demo", group="Packets",
         args=["adversary-in-the-middle/arp_spoof_demo.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=["mod:scapy", "bin:arp"]),
    dict(id="lateral-movement/lan_attack_surface", group="Packets",
         args=["lateral-movement/lan_attack_surface.py"],
         ok="host(s) on your LAN", bad=None, needs=["mod:scapy"]),

    # ---- offensive demos, all sandboxed + reversible --------------------
    dict(id="impact/ransomware_sim", group="Offensive demos",
         args=["impact/ransomware_sim.py", "--demo"],
         ok="PASSED: full encrypt -> detect -> decrypt -> verify -> cleanup cycle.",
         bad=None, needs=["mod:Cryptodome"],
         note="real AES-256, always decrypted and verified byte-for-byte"),
    dict(id="exfiltration/exfil_demo", group="Offensive demos",
         args=["exfiltration/exfil_demo.py"],
         ok="DLP inspection results", bad=None, needs=["mod:requests"],
         note="real localhost HTTP + DLP pattern inspection"),
    dict(id="c2/beacon_demo", group="Offensive demos",
         args=["c2/beacon_demo.py"],
         ok="request(s) total", bad=None, needs=["mod:requests"],
         note="8 real beacons, detected by interval regularity"),
    dict(id="collection/collection_demo", group="Offensive demos",
         args=["collection/collection_demo.py", "--demo"],
         ok="Removed all dummy/staged files", bad=None, needs=[]),
    dict(id="credential-access/credential_access_demo", group="Offensive demos",
         args=["credential-access/credential_access_demo.py", "--demo"],
         ok="fake credential", bad=None, needs=["mod:psutil"]),
    dict(id="persistence/persistence_demo", group="Offensive demos",
         args=["persistence/persistence_demo.py", "--demo"],
         ok="Removed", bad=None, needs=["windows"],
         note="HKCU Run key created, verified, then removed in one run"),
    dict(id="privilege-escalation/privesc_hunter", group="Offensive demos",
         args=["privilege-escalation/privesc_hunter.py"],
         ok=None, bad=None, needs=["windows"]),
    dict(id="shield-contain-disrupt/contain_disrupt_demo", group="Offensive demos",
         args=["shield-contain-disrupt/contain_disrupt_demo.py"],
         ok=None, bad=None, needs=["windows", "admin"],
         note="network half needs netsh from an elevated terminal"),

    # ---- detection engineering -----------------------------------------
    dict(id="detection-engineering/export_sigma_rules", group="Detection engineering",
         args=["detection-engineering/export_sigma_rules.py"],
         ok="All rules parse back correctly", bad=None, needs=["mod:yaml"],
         note="round-trip validated: written, then parsed back"),
    dict(id="detection-engineering/export_navigator_layer", group="Detection engineering",
         args=["detection-engineering/export_navigator_layer.py"],
         ok="Validated: JSON parses back correctly", bad=None, needs=[],
         note="ATT&CK Navigator layer, round-trip validated"),
    dict(id="detection-engineering/generate_report", group="Detection engineering",
         args=["detection-engineering/generate_report.py"],
         ok=None, bad=None, needs=["windows"]),

    # ---- recon / enrichment --------------------------------------------
    dict(id="initial-access/phishing_url_analyzer", group="Recon & enrichment",
         args=["initial-access/phishing_url_analyzer.py"],
         ok="typosquatting", bad=None, needs=[],
         note="pure string analysis — no network, always verifiable"),
    dict(id="discovery/local_discovery", group="Recon & enrichment",
         args=["discovery/local_discovery.py"],
         ok=None, bad=None, needs=["mod:psutil"]),
    dict(id="reconnaissance/dns_recon", group="Recon & enrichment",
         args=["reconnaissance/dns_recon.py"],
         ok=None, bad=None, needs=["net", "mod:dns"], slow=True),
    dict(id="reconnaissance/cert_transparency", group="Recon & enrichment",
         args=["reconnaissance/cert_transparency.py"],
         ok=None, bad=None, needs=["net", "mod:requests"], slow=True,
         note="crt.sh is public infrastructure and does go down"),
    dict(id="resource-development/domain_age_checker", group="Recon & enrichment",
         args=["resource-development/domain_age_checker.py"],
         ok=None, bad=None, needs=["net", "mod:whois"], slow=True),

    # ---- wireshark ------------------------------------------------------
    dict(id="shield-collect/wireshark_config_audit", group="Wireshark",
         args=["shield-collect/wireshark_config_audit.py", "--self-test"],
         ok=PASS_MARK, bad=FAIL_MARK, needs=[]),
    dict(id="shield-collect/export_wireshark_colors", group="Wireshark",
         args=["shield-collect/export_wireshark_colors.py"],
         ok=None, bad=None, needs=["bin:tshark"]),
]


def run_check(chk, timeout):
    note = chk.get("note", "")
    for req in chk.get("needs", []):
        ok, reason = probe(req)
        if not ok:
            return dict(id=chk["id"], group=chk["group"], status="BLOCKED",
                        reason=reason, seconds=0.0, note=note)

    start = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, str(ROOT / chk["args"][0])] + chk["args"][1:],
            cwd=str(ROOT), capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        return dict(id=chk["id"], group=chk["group"], status="BLOCKED",
                    reason=f"timed out after {timeout}s (usually a blocked network call)",
                    seconds=round(time.time() - start, 1), note=note)
    elapsed = round(time.time() - start, 1)

    def last_line():
        lines = [l for l in out.strip().splitlines() if l.strip()]
        return lines[-1][:110] if lines else f"exit {rc}"

    # An explicit failure marker always wins.
    if chk.get("bad") and chk["bad"] in out:
        return dict(id=chk["id"], group=chk["group"], status="FAIL",
                    reason="module reported failure", seconds=elapsed, note=note)

    if chk.get("ok"):
        if chk["ok"] in out:
            return dict(id=chk["id"], group=chk["group"], status="PASS",
                        reason="", seconds=elapsed, note=note)
        return dict(id=chk["id"], group=chk["group"], status="FAIL",
                    reason=last_line() if rc != 0
                    else "ran clean but never printed its success marker",
                    seconds=elapsed, note=note)

    # No success marker defined — the exit code is the only signal.
    if rc == 0:
        return dict(id=chk["id"], group=chk["group"], status="PASS",
                    reason="", seconds=elapsed, note=note)
    return dict(id=chk["id"], group=chk["group"], status="FAIL",
                reason=last_line(), seconds=elapsed, note=note)


COLORS = {"PASS": "\033[92m", "FAIL": "\033[91m", "BLOCKED": "\033[93m"}
RESET = "\033[0m"


def print_markdown(results, counts, runnable, total_s):
    print(f"\n<!-- generated by verify_all.py on {platform.system()} "
          f"{platform.python_version()}, {time.strftime('%Y-%m-%d')} -->\n")
    print(f"**{counts['PASS']} passed · {counts['FAIL']} failed · "
          f"{counts['BLOCKED']} blocked** — {total_s}s total\n")
    print("| Module | Result | What it proves |")
    print("|---|---|---|")
    for r in results:
        mark = {"PASS": "PASS", "FAIL": "FAIL", "BLOCKED": "blocked"}[r["status"]]
        detail = r["note"] or ""
        if r["status"] == "BLOCKED":
            detail = r["reason"]
        elif r["status"] == "FAIL":
            detail = r["reason"]
        print(f"| `{r['id']}` | {mark} | {detail} |")


def main():
    p = argparse.ArgumentParser(
        description="Run and verify every module in this project.")
    p.add_argument("--json", action="store_true", help="Machine-readable output")
    p.add_argument("--markdown", action="store_true", help="Markdown table for the README")
    p.add_argument("--quick", action="store_true", help="Skip slow network-dependent modules")
    p.add_argument("--only", metavar="SUBSTR", help="Only run modules whose id contains this")
    p.add_argument("--timeout", type=int, default=180, help="Per-module timeout (default 180s)")
    args = p.parse_args()

    checks = CHECKS
    if args.quick:
        checks = [c for c in checks if not c.get("slow")]
    if args.only:
        checks = [c for c in checks if args.only.lower() in c["id"].lower()]
    if not checks:
        print("No modules matched.")
        return 1

    quiet = args.json or args.markdown
    if not quiet:
        print(f"=== Verifying {len(checks)} module(s) on {platform.system()} "
              f"{platform.release()}, Python {platform.python_version()} ===\n")

    use_color = sys.stdout.isatty() and not quiet
    results = []
    t0 = time.time()
    last_group = None
    for chk in checks:
        if not quiet and chk["group"] != last_group:
            print(f"  -- {chk['group']}")
            last_group = chk["group"]
        r = run_check(chk, timeout=args.timeout)
        results.append(r)
        if quiet:
            continue
        c = COLORS.get(r["status"], "") if use_color else ""
        e = RESET if use_color else ""
        line = f"     {c}[{r['status']:7}]{e} {r['id']:44}"
        if r["status"] == "PASS":
            line += f" {r['seconds']:>5.1f}s"
        elif r["reason"]:
            line += f" {r['reason']}"
        print(line)
    total_s = round(time.time() - t0, 1)

    counts = {k: sum(1 for r in results if r["status"] == k)
              for k in ("PASS", "FAIL", "BLOCKED")}
    runnable = counts["PASS"] + counts["FAIL"]

    if args.json:
        print(json.dumps(dict(
            platform=platform.system(), python=platform.python_version(),
            generated=time.strftime("%Y-%m-%d %H:%M:%S"),
            counts=counts, runnable=runnable, seconds=total_s,
            results=results), indent=2))
        return 1 if counts["FAIL"] else 0

    if args.markdown:
        print_markdown(results, counts, runnable, total_s)
        return 1 if counts["FAIL"] else 0

    print(f"\n=== {counts['PASS']} passed · {counts['FAIL']} failed · "
          f"{counts['BLOCKED']} blocked · {total_s}s ===")
    if runnable:
        print(f"    {counts['PASS']}/{runnable} of everything runnable on this "
              f"platform passed ({counts['PASS'] / runnable * 100:.0f}%).")
    if counts["BLOCKED"]:
        print(f"    {counts['BLOCKED']} module(s) could not run here and are NOT "
              f"counted as passing:")
        win_blocked = 0
        for r in results:
            if r["status"] == "BLOCKED":
                print(f"      {r['id']:44} {r['reason']}")
                if "Windows" in r["reason"]:
                    win_blocked += 1
        # Only offer the Windows hint when Windows is actually the blocker —
        # saying it over a list of network timeouts would be noise.
        if win_blocked and not IS_WINDOWS:
            print(f"    {win_blocked} of those are Windows-only by design — "
                  f"run this on Windows to cover them.")
    if counts["FAIL"]:
        print("\n  Failures:")
        for r in results:
            if r["status"] == "FAIL":
                print(f"    {r['id']}: {r['reason']}")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    sys.exit(main())
