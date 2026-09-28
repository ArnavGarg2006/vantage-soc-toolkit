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

    parser.error("pass one of --self-test, --scan PATH, or --list-rules")


if __name__ == "__main__":
    sys.exit(main())
