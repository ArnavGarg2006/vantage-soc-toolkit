#!/usr/bin/env python
"""
Containment primitives for the SOAR runner — the safety layer, kept in its
own module precisely because it is the part that can do damage.

Everything else in this project observes. This is the first component that
*acts*, so it is built the way real SOAR containment is gated rather than
the way a demo would be.

THE THREAT NOBODY MENTIONS IN THE PRODUCT BROCHURE
--------------------------------------------------
A playbook that contains "the process named in the alert" is only as
trustworthy as the alert. Alert content is attacker-influenceable: a
filename, a process name, a URL in a request — these originate outside the
host's trust boundary. An attacker who can get a string into an alert can
make an auto-containment system act on a target of their choosing. That
turns your SOAR into a denial-of-service primitive aimed at your own
estate, triggered on demand.

So this module assumes the target may be hostile input and layers
accordingly:

  1. DRY RUN BY DEFAULT. Nothing acts unless explicitly armed. A plan is
     always produced and always shown; executing it is a separate decision.
  2. A PROTECTED SET THAT CANNOT BE OVERRIDDEN. init/PID 1, kernel threads,
     this process and its ancestors, and a list of names whose death takes
     the box with them. No flag disables this — a containment tool with an
     "ignore safety" switch grows a user who sets it permanently.
  3. OPTIONAL ALLOWLIST. In allowlist mode nothing is actioned unless its
     name matches. This is the configuration a real deployment runs: you
     decide in advance what may be contained, not at alert time.
  4. REVERSIBLE FIRST. SUSPEND is preferred over KILL and is the default
     action. A suspended process can be resumed with full state; a killed
     one cannot. Evidence is destroyed by termination.
  5. A JOURNAL. Every executed action is recorded in the same SQLite store
     as events and cases, so `--undo` can reverse it and so a case carries
     the audit trail of what was done on its behalf.

Usage:
    python soar/containment.py --self-test
    python soar/containment.py --list                 # journal of actions taken
    python soar/containment.py --undo 3               # reverse action #3
    python soar/containment.py --undo-all
"""
import argparse
import os
import sqlite3
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

DB_PATH = PROJECT_ROOT / "event-bus" / "events.db"
IS_WINDOWS = sys.platform.startswith("win")

SELF_TEST_MARKER = "containment_self_test"

# Names that must never be contained: processes whose death takes the
# machine, the session, or the security tooling down with it. That is the
# one outcome worse than the incident you were responding to.
#
# Intentionally not configurable. Every "disable safety checks" option ever
# shipped has ended up permanently enabled in some deployment.
#
# WHAT THIS LIST IS NOT FOR, learned by getting it wrong: the first version
# also listed python/python3/bash/sh, on the reasoning that "this project
# runs on those." That is the wrong mechanism in both directions. It is
# over-broad — on a Linux host a large share of everything is a Python or
# shell process, so containment refuses nearly every legitimate target and
# the feature is useless. And it is under-protective — an attacker's payload
# is very often a Python script or a shell, so the names carry no signal
# about whether containing one is safe.
#
# Protecting *this* tool from containing *itself* is a PID problem, not a
# name problem, and protected_pids() + ancestors_of_self() already solve it
# precisely. The self-test caught this: it spawned a Python victim and the
# guard refused to touch it.
PROTECTED_NAMES = {
    # POSIX core — killing these ends the box or every remote session on it
    "init", "systemd", "systemd-journald", "systemd-logind", "dbus-daemon",
    "kthreadd", "sshd", "login",
    # Windows core — terminating any of these bluescreens or logs everyone out
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe",
    "fontdrvhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe",
    # Security tooling — containing your own sensors is self-inflicted blindness
    "msmpeng.exe", "mssense.exe", "sensecncproxy.exe", "windefend",
}

ACTIONS = ("SUSPEND", "KILL", "BLOCK_IP")

# RFC 5737 TEST-NET-3 — reserved for documentation, nothing real is ever
# reachable there. The same range contain_disrupt_demo.py already uses, so
# the network half can be exercised without touching a real destination.
SAFE_DEMO_CIDR = "203.0.113.0/24"


def require_psutil():
    try:
        import psutil
        return psutil
    except ImportError:
        print("psutil isn't installed — needed to inspect and contain processes.")
        print("    pip install -r requirements.txt")
        sys.exit(1)


# --------------------------------------------------------------------------
# Journal — in the same database as events and cases, so an action can be
# joined to the alert that caused it.
# --------------------------------------------------------------------------

def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS containment_actions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            target_name TEXT,
            case_id INTEGER,
            event_id INTEGER,
            armed INTEGER NOT NULL,
            result TEXT NOT NULL,
            reversed_at REAL
        )
    """)
    conn.commit()


def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def journal(conn, action, target, target_name, armed, result,
            case_id=None, event_id=None):
    cur = conn.execute(
        "INSERT INTO containment_actions "
        "(ts, action, target, target_name, case_id, event_id, armed, result) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (time.time(), action, str(target), target_name, case_id, event_id,
         1 if armed else 0, result),
    )
    conn.commit()
    return cur.lastrowid


# --------------------------------------------------------------------------
# Guards
# --------------------------------------------------------------------------

def protected_pids():
    """This process, its parent, and PID 1. Containing any of them is either
    suicide or takes the box down."""
    pids = {1, os.getpid()}
    try:
        pids.add(os.getppid())
    except (AttributeError, OSError):
        pass
    return pids


def ancestors_of_self(psutil):
    """Full ancestry, not just the immediate parent. Suspending a grandparent
    shell hangs this process just as effectively as suspending its parent."""
    out = set()
    try:
        p = psutil.Process(os.getpid())
        for a in p.parents():
            out.add(a.pid)
    except Exception:
        pass
    return out


def check_target(psutil, pid, allowlist=None):
    """Decide whether `pid` may be contained.

    Returns (allowed: bool, name: str, reason: str). The reason is always
    populated on refusal and is meant to be shown — a containment system
    that silently declines is indistinguishable from one that is broken.
    """
    try:
        proc = psutil.Process(pid)
        name = proc.name()
    except Exception as e:
        return (False, "?", f"process not found or unreadable ({type(e).__name__})")

    if pid in protected_pids() or pid in ancestors_of_self(psutil):
        return (False, name, "protected: this process, an ancestor of it, or PID 1")

    if name.lower() in PROTECTED_NAMES:
        return (False, name, f"protected: '{name}' is on the never-contain list")

    if not IS_WINDOWS:
        try:
            if not proc.cmdline():
                return (False, name, "protected: kernel thread")
        except Exception:
            pass

    if allowlist is not None:
        if not any(a.lower() in name.lower() for a in allowlist):
            return (False, name,
                    f"not in the allowlist ({', '.join(allowlist) or 'empty'})")

    return (True, name, "")


# --------------------------------------------------------------------------
# Plan / execute
# --------------------------------------------------------------------------

def plan(psutil, action, target, allowlist=None):
    """Build a plan without touching anything. Always safe to call."""
    action = action.upper()
    if action not in ACTIONS:
        return dict(action=action, target=target, allowed=False,
                    name="?", reason=f"unknown action (known: {', '.join(ACTIONS)})")

    if action == "BLOCK_IP":
        # Network blocking is scoped to the documentation-only range unless
        # armed with an explicit CIDR. A playbook that firewalls an arbitrary
        # address out of an alert is the DoS primitive described above,
        # pointed at the network instead of at processes.
        allowed = str(target).startswith("203.0.113.")
        return dict(action=action, target=target, name="(network)",
                    allowed=allowed,
                    reason="" if allowed else
                    f"refused: only {SAFE_DEMO_CIDR} (RFC 5737 TEST-NET-3) may be "
                    f"blocked by an automated playbook in this project")

    allowed, name, reason = check_target(psutil, int(target), allowlist)
    return dict(action=action, target=int(target), name=name,
                allowed=allowed, reason=reason)


def execute(conn, psutil, p, armed=False, case_id=None, event_id=None):
    """Carry out a plan. With armed=False nothing happens and the journal
    records the intent — which is still worth recording, because "what would
    this playbook have done" is the question you want answered before you
    ever arm it."""
    if not p["allowed"]:
        journal(conn, p["action"], p["target"], p["name"], armed,
                f"REFUSED: {p['reason']}", case_id, event_id)
        return f"REFUSED {p['action']} on {p['target']} — {p['reason']}"

    if not armed:
        journal(conn, p["action"], p["target"], p["name"], False,
                "DRY RUN: would have executed", case_id, event_id)
        return (f"DRY RUN: would {p['action']} {p['target']} ({p['name']}) — "
                f"nothing was done; pass --arm to act")

    try:
        if p["action"] == "SUSPEND":
            psutil.Process(p["target"]).suspend()
            result = "SUSPENDED (reversible — resume with --undo)"
        elif p["action"] == "KILL":
            psutil.Process(p["target"]).terminate()
            result = "TERMINATED (not reversible)"
        elif p["action"] == "BLOCK_IP":
            result = block_ip(p["target"])
        else:
            result = f"unknown action {p['action']}"
    except Exception as e:
        result = f"FAILED: {type(e).__name__}: {e}"

    jid = journal(conn, p["action"], p["target"], p["name"], True, result,
                  case_id, event_id)
    emit(source="soar_containment", technique_id="DTE0011",
         severity="HIGH",
         message=f"{p['action']} on {p['target']} ({p['name']}): {result}")
    return f"[#{jid}] {p['action']} {p['target']} ({p['name']}) -> {result}"


def block_ip(cidr):
    import subprocess
    if IS_WINDOWS:
        rule = f"PyCyberSOAR_Block_{cidr.replace('/', '_').replace('.', '_')}"
        cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
               f"name={rule}", "dir=out", "action=block", f"remoteip={cidr}"]
    else:
        cmd = ["iptables", "-A", "OUTPUT", "-d", cidr, "-j", "DROP"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        if r.returncode == 0:
            return f"BLOCKED {cidr}"
        return f"FAILED (rc={r.returncode}): {(r.stderr or r.stdout).strip()[:90]}"
    except FileNotFoundError:
        return f"FAILED: {cmd[0]} not available on this host"
    except Exception as e:
        return f"FAILED: {type(e).__name__}: {e}"


def undo(conn, psutil, action_id):
    row = conn.execute("SELECT * FROM containment_actions WHERE id = ?",
                       (action_id,)).fetchone()
    if row is None:
        return f"no action #{action_id}"
    if row["reversed_at"]:
        return f"action #{action_id} was already reversed"
    if not row["armed"]:
        return f"action #{action_id} was a dry run — nothing to reverse"

    act = row["action"]
    if act == "SUSPEND":
        try:
            psutil.Process(int(row["target"])).resume()
            result = f"resumed pid {row['target']}"
        except Exception as e:
            result = f"could not resume pid {row['target']}: {type(e).__name__}"
    elif act == "BLOCK_IP":
        result = unblock_ip(row["target"])
    elif act == "KILL":
        # Stated rather than silently skipped. This is the argument for
        # preferring SUSPEND, made at the moment it matters.
        return (f"action #{action_id} was a KILL — a terminated process cannot "
                f"be restored. This is why SUSPEND is the default.")
    else:
        result = f"no undo defined for {act}"

    conn.execute("UPDATE containment_actions SET reversed_at = ? WHERE id = ?",
                 (time.time(), action_id))
    conn.commit()
    return f"action #{action_id} reversed: {result}"


def unblock_ip(cidr):
    import subprocess
    if IS_WINDOWS:
        rule = f"PyCyberSOAR_Block_{cidr.replace('/', '_').replace('.', '_')}"
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"]
    else:
        cmd = ["iptables", "-D", "OUTPUT", "-d", cidr, "-j", "DROP"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return f"unblocked {cidr}" if r.returncode == 0 else \
            f"unblock failed (rc={r.returncode})"
    except Exception as e:
        return f"unblock failed: {type(e).__name__}"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_list(conn):
    rows = conn.execute(
        "SELECT * FROM containment_actions ORDER BY id DESC LIMIT 50").fetchall()
    print(f"=== {len(rows)} containment action(s), newest first ===\n")
    if not rows:
        print("  None recorded.")
        return
    print(f"  {'ID':>4}  {'WHEN':20} {'MODE':8} {'ACTION':9} {'TARGET':>8} "
          f"{'NAME':18} RESULT")
    for r in rows:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
        mode = "ARMED" if r["armed"] else "dry-run"
        rev = "  (reversed)" if r["reversed_at"] else ""
        print(f"  {r['id']:>4}  {when:20} {mode:8} {r['action']:9} "
              f"{str(r['target']):>8} {(r['target_name'] or '?'):18} "
              f"{r['result'][:46]}{rev}")


def self_test():
    import subprocess
    psutil = require_psutil()
    print("=== Containment self-test ===\n")
    print("  Every action below targets a process this test spawned itself.")
    print("  Nothing pre-existing on this machine is ever touched.\n")

    conn = connect()
    before = conn.execute(
        "SELECT COALESCE(MAX(id), 0) m FROM containment_actions").fetchone()["m"]

    victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    time.sleep(0.8)
    checks = []

    # 1. Dry run must not change the process at all.
    p = plan(psutil, "SUSPEND", victim.pid)
    out = execute(conn, psutil, p, armed=False)
    status_after_dry = psutil.Process(victim.pid).status()
    checks.append(("dry run leaves the process running untouched",
                   "DRY RUN" in out and status_after_dry != psutil.STATUS_STOPPED))

    # 2. Armed suspend must actually stop it.
    out = execute(conn, psutil, p, armed=True)
    time.sleep(0.4)
    suspended = psutil.Process(victim.pid).status() == psutil.STATUS_STOPPED
    checks.append(("armed SUSPEND actually stops the process", suspended))

    # 3. Undo must resume it — containment that can't be reversed is an outage.
    last_id = conn.execute(
        "SELECT MAX(id) m FROM containment_actions WHERE armed=1").fetchone()["m"]
    undo(conn, psutil, last_id)
    time.sleep(0.4)
    resumed = psutil.Process(victim.pid).status() != psutil.STATUS_STOPPED
    checks.append(("--undo resumes the suspended process", resumed))

    # 4. Self-protection: refusing to contain ourselves.
    p_self = plan(psutil, "SUSPEND", os.getpid())
    checks.append(("refuses to contain its own process",
                   not p_self["allowed"] and "protected" in p_self["reason"]))

    # 5. PID 1.
    p_init = plan(psutil, "KILL", 1)
    checks.append(("refuses to contain PID 1", not p_init["allowed"]))

    # 6. The never-contain list covers catastrophic processes, and NOT
    #    ubiquitous interpreters. Asserting the policy itself, because the
    #    first version of this list got the distinction wrong and made
    #    containment refuse almost every legitimate target.
    catastrophic = {"init", "systemd", "lsass.exe", "csrss.exe", "winlogon.exe"}
    ubiquitous = {"python", "python3", "bash", "sh", "zsh"}
    checks.append(("never-contain list covers catastrophic processes only",
                   catastrophic <= PROTECTED_NAMES
                   and not (ubiquitous & PROTECTED_NAMES)))

    # 7. Allowlist mode refuses anything not named in it.
    p_allow = plan(psutil, "SUSPEND", victim.pid, allowlist=["definitely-not-this"])
    checks.append(("allowlist mode refuses a non-matching target",
                   not p_allow["allowed"] and "allowlist" in p_allow["reason"]))

    # 8. Network blocking is confined to the documentation range.
    p_bad_ip = plan(psutil, "BLOCK_IP", "8.8.8.8")
    p_ok_ip = plan(psutil, "BLOCK_IP", "203.0.113.5")
    checks.append(("BLOCK_IP refuses a real address, allows only TEST-NET-3",
                   not p_bad_ip["allowed"] and p_ok_ip["allowed"]))

    # 9. A KILL is honestly reported as irreversible rather than silently skipped.
    kill_id = journal(conn, "KILL", victim.pid, "test", True, "TERMINATED (not reversible)")
    msg = undo(conn, psutil, kill_id)
    checks.append(("undo of a KILL says plainly that it cannot be reversed",
                   "cannot be restored" in msg))

    victim.terminate()
    try:
        victim.wait(timeout=5)
    except Exception:
        victim.kill()

    print()
    for label, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    passed = all(ok for _, ok in checks)

    conn.execute("DELETE FROM containment_actions WHERE id > ?", (before,))
    conn.commit()
    left = conn.execute(
        "SELECT COUNT(*) c FROM containment_actions WHERE id > ?", (before,)
    ).fetchone()["c"]
    print(f"\n  Cleanup: removed this test's journal rows ({left} left); "
          f"the spawned process was terminated. Real history untouched.")
    conn.close()

    print(f"\nSelf-test {'PASSED' if passed else 'FAILED'}")
    return 0 if passed else 1


def main():
    p = argparse.ArgumentParser(
        description="Containment primitives for the SOAR runner — dry-run by default.")
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--list", action="store_true", help="Show the containment journal")
    p.add_argument("--undo", type=int, metavar="ID", help="Reverse one journalled action")
    p.add_argument("--undo-all", action="store_true",
                   help="Reverse every reversible action still in effect")
    args = p.parse_args()

    if args.self_test:
        return self_test()
    if not (args.list or args.undo or args.undo_all):
        p.error("pass one of --self-test, --list, --undo ID, --undo-all")

    conn = connect()
    if args.list:
        cmd_list(conn)
    if args.undo:
        print(undo(conn, require_psutil(), args.undo))
    if args.undo_all:
        psutil = require_psutil()
        rows = conn.execute(
            "SELECT id FROM containment_actions WHERE armed=1 AND reversed_at IS NULL "
            "AND action != 'KILL' ORDER BY id DESC").fetchall()
        if not rows:
            print("Nothing reversible is currently in effect.")
        for r in rows:
            print(" ", undo(conn, psutil, r["id"]))
    conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
