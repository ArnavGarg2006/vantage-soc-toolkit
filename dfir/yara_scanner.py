#!/usr/bin/env python
"""
YARA scanner — DFIR. The file/memory-side counterpart to the log-side
Sigma rules this project already exports.

Why YARA and not one of the other tools on the usual "SOC stack" list:
MISP, OpenCTI, TheHive, XSOAR, Nessus and friends are server platforms.
Writing an API client for a platform that isn't running anywhere would
produce exactly what this project refuses to ship — code whose output was
never verified because it can't be. YARA is the one industry-standard
tool on that list that installs with pip, runs entirely locally, and can
be proven correct on this machine in one command.

What makes the rules in rules/ honest: every one of them is run against
a file that SHOULD match it and a benign control file that should NOT,
in the same --self-test. A rule that has only ever been eyeballed is a
guess. The true-positive samples aren't invented for the test either —
they're the artifacts this repo's own demos actually produce
(exfil_demo.py's DLP payload, ransomware_sim.py's AES-256 output,
persistence_demo.py's Run-key command line).

Two caveats stated up front rather than buried, because both are real:

  - PyCyber_High_Entropy_Blob is corroboration, not a verdict. Compressed
    archives, media files and installers are legitimately high-entropy.
    It is scoped to small files and reported at MEDIUM for that reason.
  - Scanning this repo with these rules matches this repo's own
    detection content. rules/*.yar literally contains the strings
    "certutil", "-urlcache" and "FromBase64String"; so do
    shield-detect/process_monitor.py, detection-engineering/
    export_sigma_rules.py and this file's own sample generator. Found by
    running --scan on the repo, not predicted: the first version of this
    scanner only skipped .yar/.yml and still reported 9 HIGH matches
    against the project itself.

    That is not a bug in YARA and not a reason to weaken the rules — it
    is the ordinary false-positive class every real deployment hits when
    the scanner walks over its own signatures, and real deployments solve
    it with an exclusion list. So does this one: DETECTION_CONTENT below
    is skipped by default and the count of suppressed files is always
    printed, never silently dropped. --include-detection-content turns
    the exclusion off so you can watch it happen.

Usage:
    python dfir/yara_scanner.py --self-test
    python dfir/yara_scanner.py --scan <file-or-directory>
    python dfir/yara_scanner.py --scan <dir> --include-detection-content
    python dfir/yara_scanner.py --list-rules
"""
import argparse
import os
import shutil
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

RULES_DIR = Path(__file__).resolve().parent / "rules"
SCRATCH_DIR = Path(__file__).resolve().parent / "scratch"

# Files above this size are skipped with a printed note rather than silently.
# YARA itself is fine with large files; the point is that a DFIR scan that
# quietly skipped something is worse than one that says it did.
MAX_SCAN_BYTES = 32 * 1024 * 1024

# Skipped by default — see the module docstring. Detection content contains
# the very strings it detects, so scanning it produces guaranteed false
# positives that would drown out a real hit.
RULE_CONTENT_SUFFIXES = {".yar", ".yara", ".yml", ".yaml"}

# This project's own detection sources, relative to the repo root. These are
# .py files, so the suffix skip above doesn't cover them — each one embeds
# LOLBin names, encoded-PowerShell markers or DLP patterns as its detection
# logic. Matched by path suffix so the exclusion still works no matter where
# the repo is checked out or which directory the scan is rooted at.
DETECTION_CONTENT = {
    "dfir/yara_scanner.py",
    "shield-detect/process_monitor.py",
    "detection-engineering/export_sigma_rules.py",
    "detection-engineering/attack_cti_lookup.py",
    "exfiltration/exfil_demo.py",
    "initial-access/phishing_url_analyzer.py",
    "soar/playbook_runner.py",
}

SEVERITY_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def require_yara():
    try:
        import yara
        return yara
    except ImportError:
        print("yara-python isn't installed. It ships prebuilt wheels for Windows and Linux:")
        print("    pip install yara-python")
        print("(it's in requirements.txt — `pip install -r requirements.txt` covers it)")
        sys.exit(1)


def compile_rules(yara, quiet=False):
    if not RULES_DIR.is_dir():
        print(f"No rules directory at {RULES_DIR}")
        sys.exit(1)
    sources = sorted(RULES_DIR.glob("*.yar")) + sorted(RULES_DIR.glob("*.yara"))
    if not sources:
        print(f"No .yar/.yara files in {RULES_DIR}")
        sys.exit(1)
    try:
        rules = yara.compile(filepaths={p.stem: str(p) for p in sources})
    except yara.SyntaxError as e:
        # A rule that doesn't compile is a broken detection, and saying so
        # plainly beats a traceback.
        print(f"Rule compilation FAILED: {e}")
        sys.exit(1)
    if not quiet:
        print(f"Compiled {len(sources)} rule file(s) from {RULES_DIR}")
    return rules


def severity_of(match):
    return str(match.meta.get("severity", "MEDIUM")).upper()


def scope_of(match):
    """Where a rule is valid: "file", "memory", or "both".

    Default is "file" rather than "both" deliberately. A rule written
    without thinking about memory is a file rule, and the failure mode of
    guessing wrong in that direction is a noisy memory scanner — which is
    the thing that makes people stop reading memory alerts.
    """
    return str(match.meta.get("scope", "file")).lower()


def in_scope(match, context):
    s = scope_of(match)
    return s == "both" or s == context


def scan_file(rules, path, quiet=False):
    """Returns a list of yara match objects, or None if the file was skipped."""
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_SCAN_BYTES:
        if not quiet:
            print(f"  [skip] {path} ({size / 1048576:.1f} MB > {MAX_SCAN_BYTES // 1048576} MB limit)")
        return None
    try:
        return rules.match(str(path))
    except Exception as e:
        # Locked files, permission denials and unreadable device nodes are
        # normal on a live host — report and keep going, never abort the scan.
        if not quiet:
            print(f"  [skip] {path}: {e}")
        return None


def is_detection_content(path):
    """True if this file is one of THIS project's own detection sources.

    Compared as a posix path suffix rather than an absolute path so the
    exclusion holds regardless of checkout location or scan root.
    """
    posix = path.as_posix()
    return any(posix.endswith(rel) for rel in DETECTION_CONTENT)


def iter_targets(root, include_detection_content, excluded):
    """Yields files to scan. `excluded` is a list this appends skipped
    detection-content paths to, so the caller can report the count instead
    of the exclusion being invisible."""
    if root.is_file():
        if not include_detection_content and (
            root.suffix.lower() in RULE_CONTENT_SUFFIXES or is_detection_content(root)
        ):
            excluded.append(root)
            return
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        # Never walk into .git — it's thousands of objects and none of them
        # are what a DFIR scan is looking for.
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__", ".venv", "venv"}]
        for name in sorted(filenames):
            p = Path(dirpath) / name
            if not include_detection_content and (
                p.suffix.lower() in RULE_CONTENT_SUFFIXES or is_detection_content(p)
            ):
                excluded.append(p)
                continue
            yield p


def run_scan(rules, target, include_detection_content=False, quiet=False, emit_events=True):
    root = Path(target).resolve()
    if not root.exists():
        print(f"No such path: {root}")
        sys.exit(1)

    # quiet=True suppresses ALL console output, not just the per-hit lines.
    # soar/playbook_runner.py calls this as a library and renders the results
    # itself; a scanner that narrates into the middle of a playbook's output
    # makes the automation log unreadable.
    if not quiet:
        print(f"\n=== Scanning {root} ===")

    scanned = 0
    hits = []
    excluded = []
    for path in iter_targets(root, include_detection_content, excluded):
        matches = scan_file(rules, path, quiet=quiet)
        if matches is None:
            continue
        scanned += 1
        for m in matches:
            if not in_scope(m, "file"):
                continue
            hits.append((path, m))
            severity = severity_of(m)
            desc = m.meta.get("description", "")
            if not quiet:
                print(f"  [{severity:6}] {m.rule}")
                print(f"           {path}")
                print(f"           {desc}")
            if emit_events:
                emit(
                    source="yara_scanner",
                    technique_id=str(m.meta.get("attack", "")).split(",")[0].strip(),
                    severity=severity,
                    message=f"{m.rule} matched {path.name}: {desc}",
                )

    if quiet:
        return hits

    print(f"\n  {scanned} file(s) scanned, {len(hits)} match(es).")
    if excluded:
        # Always printed, never silent — an exclusion you can't see is
        # indistinguishable from a rule that failed to fire.
        print(f"  {len(excluded)} file(s) excluded as detection content "
              f"(rules and detectors embed the strings they detect — "
              f"--include-detection-content to scan them anyway):")
        for p in excluded[:8]:
            print(f"      {p.name}")
        if len(excluded) > 8:
            print(f"      ... and {len(excluded) - 8} more")
    if hits:
        worst = max(SEVERITY_ORDER.get(severity_of(m), 0) for _, m in hits)
        worst_name = next(k for k, v in SEVERITY_ORDER.items() if v == worst)
        print(f"  Highest severity: {worst_name}")
        if any(m.rule == "PyCyber_High_Entropy_Blob" for _, m in hits):
            print("  Note: PyCyber_High_Entropy_Blob fired. Entropy alone is corroboration, "
                  "not proof — archives, media and installers are legitimately high-entropy.")
    return hits


# --------------------------------------------------------------------------
# Live process-memory scanning.
#
# The gap this closes: everything above reads files. An attacker who decodes
# a payload in memory, or holds credentials in a process after reading them,
# leaves nothing on disk for a file scan to find. yara-python exposes
# rules.match(pid=...) for exactly this, and it is the same rule set — a
# YARA rule does not care where the bytes came from.
#
# Three things about memory scanning that are genuinely different from
# scanning files, all of which the code below has to handle rather than
# pretend away:
#
#   1. It needs privilege. Reading another process's memory means root (or
#      same-user plus ptrace permission) on Linux, and an elevated terminal
#      plus SeDebugPrivilege on Windows. Denials are normal and are counted
#      and reported, never silently dropped.
#   2. It is slow and it is noisy. A full sweep walks every mapped region of
#      every process, and memory legitimately contains strings that look
#      alarming — a browser tab, a password manager, a terminal scrollback.
#      Severities in the memory rules are set conservatively for that reason
#      and the scanner says so inline.
#   3. The scanner self-matches. This process holds every rule string in its
#      own memory, because it just compiled them. That is the runtime twin
#      of the detection-content problem the file scanner already has, and it
#      is handled the same way: the scanner's own PID (and its parent) are
#      excluded by default, visibly, with a flag to turn that off so you can
#      watch it happen.
# --------------------------------------------------------------------------

# A full sweep of every process on a busy host is minutes of work for very
# little return. The cap keeps the default honest and is reported when hit.
IS_WINDOWS = sys.platform.startswith("win")

DEFAULT_MAX_PROCESSES = 60


def require_psutil():
    try:
        import psutil
        return psutil
    except ImportError:
        print("psutil isn't installed (needed to enumerate processes).")
        print("    pip install -r requirements.txt")
        sys.exit(1)


def scan_process(rules, pid, timeout=20):
    """Scan one live process's memory.

    Returns (matches, error). Exactly one is meaningful: an error string
    means the scan could not happen and the caller must report it rather
    than treat it as 'clean'. Conflating 'no access' with 'no match' is the
    single easiest way to make a memory scanner look better than it is.
    """
    try:
        return (rules.match(pid=pid, timeout=timeout) or [], None)
    except Exception as e:
        msg = str(e) or type(e).__name__
        low = msg.lower()
        if "access" in low or "permission" in low or "denied" in low:
            return (None, "access denied (needs root / elevated + SeDebugPrivilege)")
        if "timeout" in low or "timed out" in low:
            return (None, f"timed out after {timeout}s")
        if "could not attach" in low or "process not found" in low or "no such" in low:
            return (None, "process exited before it could be scanned")
        return (None, msg[:90])


def is_kernel_thread(proc):
    """True for a Linux kernel thread — it has no user address space, so a
    memory scan of it can never match and reporting it as access-denied is
    actively misleading. Kernel threads expose an empty cmdline; a userland
    process always has one. Windows has no equivalent, so this is a no-op
    there and the function simply returns False."""
    if IS_WINDOWS:
        return False
    try:
        return not proc.cmdline()
    except Exception:
        # Can't tell — treat as a real process so it's scanned (and any
        # genuine denial gets reported) rather than silently dropped.
        return False


def self_pids():
    """This process and its parent — excluded by default because the scanner
    necessarily holds every rule string in its own memory."""
    pids = {os.getpid()}
    try:
        pids.add(os.getppid())
    except (AttributeError, OSError):
        pass
    return pids


def run_memory_scan(rules, pids=None, name_filter=None,
                    max_processes=DEFAULT_MAX_PROCESSES,
                    include_self=False, quiet=False, emit_events=True,
                    timeout=20):
    """Scan live process memory. Returns a list of (pid, name, match)."""
    psutil = require_psutil()
    skip = set() if include_self else self_pids()

    if pids:
        targets = []
        for pid in pids:
            try:
                targets.append((pid, psutil.Process(pid).name()))
            except Exception:
                targets.append((pid, "?"))
    else:
        targets = []
        kernel_threads = 0
        for p in psutil.process_iter(["pid", "name", "create_time"]):
            name = p.info.get("name") or "?"
            if name_filter and name_filter.lower() not in name.lower():
                continue
            # Kernel threads have no user address space at all, so a memory
            # scan of one can never match. They were previously counted as
            # "access denied", which reads as a privilege problem the user
            # could fix by running elevated — they cannot. Found by running
            # --scan-processes as root and getting 40/40 "denied".
            if not is_kernel_thread(p):
                targets.append((p.info["pid"], name, p.info.get("create_time") or 0))
            else:
                kernel_threads += 1
        # Newest first. Sorting by PID ascending spends the whole cap on
        # init and kernel threads — the least interesting processes on the
        # box. A process that appeared recently is where a fresh compromise
        # actually lives.
        targets.sort(key=lambda t: t[2], reverse=True)
        targets = [(pid, name) for pid, name, _ in targets]
        if kernel_threads and not quiet:
            print(f"\n  ({kernel_threads} kernel thread(s) skipped — no user "
                  f"address space to scan, not a permission problem)")

    capped = False
    if not pids and len(targets) > max_processes:
        targets = targets[:max_processes]
        capped = True

    if not quiet:
        print(f"\n=== Scanning process memory ({len(targets)} process(es)) ===")
        if skip:
            print(f"  (excluding this scanner's own PID{'s' if len(skip) > 1 else ''} "
                  f"{sorted(skip)} — it holds every rule string in memory by "
                  f"definition; --include-self to scan it anyway)")

    hits, denied, gone, errors, scanned = [], 0, 0, 0, 0
    for pid, name in targets:
        if pid in skip:
            continue
        matches, err = scan_process(rules, pid, timeout=timeout)
        if err is not None:
            if "denied" in err:
                denied += 1
            elif "exited" in err:
                gone += 1
            else:
                errors += 1
                if not quiet:
                    print(f"  [skip] pid {pid} ({name}): {err}")
            continue
        scanned += 1
        for m in matches:
            # Scope is enforced here, not left to the rule author's good
            # intentions. A file rule loose enough to be harmless on a 2 KB
            # sample is near-guaranteed to fire somewhere in 50 MB of
            # address space — measured, see pycyber_artifacts.yar's header.
            if not in_scope(m, "memory"):
                continue
            hits.append((pid, name, m))
            severity = severity_of(m)
            if not quiet:
                print(f"  [{severity:6}] {m.rule}")
                print(f"           pid {pid} ({name})")
                print(f"           {m.meta.get('description', '')}")
            if emit_events:
                emit(source="yara_scanner",
                     technique_id=str(m.meta.get("attack", "")).split(",")[0].strip(),
                     severity=severity,
                     message=f"{m.rule} matched LIVE MEMORY of pid {pid} ({name}): "
                             f"{m.meta.get('description', '')}")

    if quiet:
        return hits

    print(f"\n  {scanned} process(es) scanned, {len(hits)} match(es).")
    # Every category of non-scan is reported. A memory scanner that silently
    # skips what it could not read is reporting the privilege it has, not
    # the state of the host.
    if denied:
        print(f"  {denied} process(es) could not be read (access denied) — "
              f"{'run elevated to cover them' if denied else ''}")
    if gone:
        print(f"  {gone} process(es) exited mid-scan (normal on a live host)")
    if errors:
        print(f"  {errors} process(es) failed for other reasons (listed above)")
    if capped:
        print(f"  Capped at {max_processes} process(es) — raise with --max-processes")
    if hits:
        print("  Note: memory legitimately contains alarming-looking strings "
              "(browsers, password managers, shells). Treat a memory hit as a "
              "lead to confirm, not a verdict.")
    return hits


# --------------------------------------------------------------------------
# Self-test: generate one true-positive sample per rule plus a benign control,
# then assert each rule fires on exactly the sample it's meant for.
# --------------------------------------------------------------------------

def build_samples():
    """Writes the sample files and returns {filename: expected_rule_or_None}.

    The samples are the artifacts this repo's own demos produce, not
    invented strings — that's what makes the rules mean something.
    """
    SCRATCH_DIR.mkdir(exist_ok=True)
    expected = {}

    # 1. Encoded PowerShell — the same shape persistence/privesc detection
    #    already flags on the command-line side.
    p = SCRATCH_DIR / "sample_encoded_ps.txt"
    p.write_text(
        "powershell.exe -nop -w hidden -EncodedCommand "
        "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==\n"
    )
    expected[p.name] = "PyCyber_Encoded_PowerShell_Command"

    # 2. LOLBin download cradle.
    p = SCRATCH_DIR / "sample_lolbin_cradle.txt"
    p.write_text("certutil.exe -urlcache -split -f http://127.0.0.1/payload.txt payload.txt\n")
    expected[p.name] = "PyCyber_LOLBin_Download_Cradle"

    # 3. Staged sensitive data — byte-for-byte the payload
    #    exfiltration/exfil_demo.py sends, which is deliberately
    #    Luhn-invalid (0000 prefix) and structurally cannot be a real card.
    p = SCRATCH_DIR / "sample_staged_data.txt"
    p.write_text(
        "user_notes=Meeting at 3pm. "
        "backup_card=0000-0000-0000-0000. "
        "ref_id=000-00-0000. "
        "nothing else interesting here.\n"
    )
    expected[p.name] = "PyCyber_Staged_Sensitive_Data"

    # 4. Ransom note.
    p = SCRATCH_DIR / "sample_ransom_note.txt"
    p.write_text(
        "!!! ALL OF YOUR FILES ARE ENCRYPTED !!!\n"
        "To decrypt them you must send 0.5 bitcoin to the address below.\n"
        "Do not attempt to use any recovery key.\n"
    )
    expected[p.name] = "PyCyber_Ransom_Note"

    # 5. High-entropy blob — generated with the SAME construction
    #    impact/ransomware_sim.py uses (AES-256 EAX, nonce + tag +
    #    ciphertext), not os.urandom, so the rule is proven against the
    #    real artifact format rather than against generic noise.
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes

    key = get_random_bytes(32)
    plaintext = ("This is disposable test content.\nNothing real is stored here.\n" * 40).encode()
    cipher = AES.new(key, AES.MODE_EAX)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    p = SCRATCH_DIR / "sample_file.txt.encrypted"
    p.write_bytes(cipher.nonce + tag + ct)
    expected[p.name] = "PyCyber_High_Entropy_Blob"

    # 6. Benign control — must match NOTHING. Without this the whole
    #    self-test proves only that the rules are loose enough to fire,
    #    which is not the same as being correct.
    p = SCRATCH_DIR / "control_benign.txt"
    p.write_text(
        "Quarterly notes. The migration finished on schedule and the team "
        "signed off. Next review is in April. No action items outstanding.\n" * 6
    )
    expected[p.name] = None

    return expected


def memory_self_test(rules, quiet=False):
    """Spawn two real processes — one holding a pattern the memory rules
    match, one benign — and prove the scanner tells them apart.

    The control process is what makes this mean anything, exactly as on the
    file side. Proving a rule fires says nothing about whether it fires on
    everything.
    """
    import subprocess

    print("\n=== Live process-memory scan ===")

    # Holds credential-shaped material in memory and never writes it to disk —
    # which is precisely what a file scan cannot see. The AKIA value is a
    # structurally-invalid placeholder, not a real key.
    bad_src = (
        "import time\n"
        "blob = 'AWS_SECRET_ACCESS_KEY' + '=' + 'x' * 20\n"
        "key = 'AKIA' + '0' * 16\n"
        "held = [blob, key, 'aws_backup_credentials']\n"
        "time.sleep(8)\n"
    )
    # Same shape of program, no matching content — the negative control.
    good_src = (
        "import time\n"
        "held = ['quarterly notes', 'migration finished on schedule', 'no action items']\n"
        "time.sleep(8)\n"
    )

    bad = subprocess.Popen([sys.executable, "-c", bad_src])
    good = subprocess.Popen([sys.executable, "-c", good_src])
    time.sleep(1.5)  # let both interpreters finish starting and hold the strings

    try:
        bad_hits = run_memory_scan(rules, pids=[bad.pid], quiet=True, emit_events=False)
        good_hits = run_memory_scan(rules, pids=[good.pid], quiet=True, emit_events=False)

        bad_rules = sorted({m.rule for _, _, m in bad_hits})
        good_rules = sorted({m.rule for _, _, m in good_hits})

        print(f"  [{'PASS' if 'PyCyber_Mem_Credential_Material' in bad_rules else 'FAIL'}] "
              f"pid {bad.pid} (credential material held in memory only) -> "
              f"{', '.join(bad_rules) or 'nothing'}")
        print(f"  [{'PASS' if not good_hits else 'FAIL'}] "
              f"pid {good.pid} (benign control process) -> "
              f"{', '.join(good_rules) or 'no match (correct)'}")

        # The self-match is a real property worth demonstrating rather than
        # asserting in a comment: this process holds every rule string.
        own = run_memory_scan(rules, pids=[os.getpid()], include_self=True,
                              quiet=True, emit_events=False)
        print(f"  [info] scanning the scanner's own PID matches "
              f"{len({m.rule for _, _, m in own})} rule(s) — which is why it is "
              f"excluded by default, not a bug")

        passed = ("PyCyber_Mem_Credential_Material" in bad_rules) and not good_hits
    finally:
        for p in (bad, good):
            p.terminate()
            try:
                p.wait(timeout=5)
            except Exception:
                p.kill()

    return passed


def self_test():
    yara = require_yara()
    print("=== YARA scanner self-test ===\n")
    rules = compile_rules(yara)

    expected = build_samples()
    print(f"Generated {len(expected)} sample file(s) in {SCRATCH_DIR}")
    print("  (5 true-positive samples + 1 benign control — a rule that was never "
          "tested against a negative hasn't been tested)\n")

    results = {}
    for name in expected:
        path = SCRATCH_DIR / name
        matches = rules.match(str(path)) or []
        results[name] = sorted(m.rule for m in matches)

    passed = True
    for name, want in expected.items():
        got = results[name]
        if want is None:
            ok = not got
            verdict = "PASS" if ok else f"FAIL (expected no match, got {got})"
        else:
            ok = want in got
            verdict = "PASS" if ok else f"FAIL (expected {want}, got {got or 'nothing'})"
        passed = passed and ok
        label = want or "no match (control)"
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:34} -> {label}")
        if not ok:
            print(f"         {verdict}")

    # The control file is the one that actually proves something about
    # false-positive rate, so call it out separately.
    control_hits = results.get("control_benign.txt", [])
    print(f"\n  Benign control matched {len(control_hits)} rule(s)"
          f"{' — ' + ', '.join(control_hits) if control_hits else ' (correct)'}")

    # Memory scanning is verified in the same run and on the same terms:
    # a live process that should match, and one that should not.
    mem_passed = memory_self_test(rules)
    passed = passed and mem_passed

    fired = emit(
        source="yara_scanner",
        technique_id="T1486",
        severity="INFO" if passed else "HIGH",
        message=f"self-test {'passed' if passed else 'FAILED'}: "
                f"{len(expected) - 1} rule(s) verified against true positives + 1 benign control",
    )
    print(f"  Event bus: {'event accepted by collector' if fired else 'collector not running (optional)'}")

    shutil.rmtree(SCRATCH_DIR, ignore_errors=True)
    print(f"  Cleaned up {SCRATCH_DIR} — nothing left behind.\n")

    print(f"Self-test {'PASSED' if passed else 'FAILED'}")
    return 0 if passed else 1


def list_rules():
    yara = require_yara()
    rules = compile_rules(yara)
    # yara-python has no public rule-introspection API, so this reads the
    # meta back off a match against a crafted buffer... which it can't do
    # without a matching file. Simpler and honest: parse the rule names and
    # meta out of the source files we just compiled.
    print()
    for src in sorted(RULES_DIR.glob("*.yar")):
        current = None
        for line in src.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("rule "):
                current = stripped.split()[1]
                print(f"  {current}")
            elif current and "=" in stripped and stripped.split("=")[0].strip() in (
                "description", "attack", "severity", "sigma_equivalent"
            ):
                k, v = stripped.split("=", 1)
                value = v.strip().strip('"')
                print(f"      {k.strip():18} {value}")
            elif stripped == "}":
                current = None
    print()
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Scan files with this project's YARA rules, or verify the rules themselves."
    )
    parser.add_argument("--self-test", action="store_true",
                        help="Generate true-positive samples + a benign control and verify every rule")
    parser.add_argument("--scan", metavar="PATH", help="Scan a file or directory")
    parser.add_argument("--include-detection-content", action="store_true",
                        help="Don't skip this project's rules and detectors (they self-match "
                             "— see module docstring)")
    parser.add_argument("--list-rules", action="store_true", help="Show the loaded rules and their metadata")
    parser.add_argument("--scan-pid", type=int, metavar="PID",
                        help="Scan one live process's memory (needs root / elevated)")
    parser.add_argument("--scan-processes", action="store_true",
                        help="Scan live process memory across running processes")
    parser.add_argument("--name-filter", metavar="SUBSTR",
                        help="With --scan-processes, only processes whose name contains this")
    parser.add_argument("--max-processes", type=int, default=DEFAULT_MAX_PROCESSES,
                        help=f"Cap for --scan-processes (default {DEFAULT_MAX_PROCESSES})")
    parser.add_argument("--include-self", action="store_true",
                        help="Don't exclude the scanner's own PID (it self-matches — see docstring)")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.list_rules:
        return list_rules()
    if args.scan:
        yara = require_yara()
        rules = compile_rules(yara)
        hits = run_scan(rules, args.scan,
                        include_detection_content=args.include_detection_content)
        return 1 if hits else 0
    if args.scan_pid or args.scan_processes:
        yara = require_yara()
        rules = compile_rules(yara)
        hits = run_memory_scan(
            rules,
            pids=[args.scan_pid] if args.scan_pid else None,
            name_filter=args.name_filter,
            max_processes=args.max_processes,
            include_self=args.include_self,
        )
        return 1 if hits else 0

    parser.error("pass one of --self-test, --scan PATH, --scan-pid PID, "
                 "--scan-processes, or --list-rules")


if __name__ == "__main__":
    sys.exit(main())
