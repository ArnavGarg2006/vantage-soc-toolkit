#!/usr/bin/env python
"""
Wireshark config audit — closes the loop on the real bug found while
building the training-pcap depth-roadmap item: this machine's Wireshark
profile has the `ip` and `http` dissectors explicitly disabled in
%APPDATA%\\Wireshark\\disabled_protos, which pcap_analysis.py now works
around per-invocation with --enable-protocol. This tool fixes the actual
root cause instead — the saved GUI profile itself — so opening a pcap in
the real Wireshark application (not just this project's scripts) shows
full dissection too.

Read-only by default. --fix requires the flag explicitly; it backs up the
original file (disabled_protos.bak) before writing, and only removes
entries from a small, deliberately curated allowlist of protocols this
project's analysis actually depends on (ip, http, tcp, udp, dns, tls,
arp) — anything else disabled in your profile is left alone, since you
may have turned it off on purpose for an unrelated reason this tool has
no way to know about.

Usage:
    python wireshark_config_audit.py            # report only, changes nothing
    python wireshark_config_audit.py --fix       # backs up, then re-enables
                                                    # only the important
                                                    # disabled protocols
    python wireshark_config_audit.py --self-test  # runs the audit/fix logic
                                                     # against a TEMP copy of
                                                     # the file format, never
                                                     # touches your real profile
"""
import shutil
import sys
import tempfile
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

REAL_DISABLED_PROTOS_PATH = Path.home() / "AppData" / "Roaming" / "Wireshark" / "disabled_protos"

# Protocols this project's own analysis tooling actually depends on -
# only these are ever candidates for re-enabling. Anything else disabled
# in a real profile is left untouched.
IMPORTANT_PROTOCOLS = {"ip", "http", "tcp", "udp", "dns", "tls", "arp"}


def audit(path):
    if not path.exists():
        print(f"{path} does not exist — nothing is explicitly disabled (default Wireshark state).")
        return []
    lines = path.read_text(encoding="utf-8").splitlines()
    disabled = [line.strip() for line in lines if line.strip()]
    important_disabled = [p for p in disabled if p in IMPORTANT_PROTOCOLS]

    print(f"=== Wireshark disabled-protocol audit: {path} ===\n")
    print(f"  {len(disabled)} protocol(s) disabled in total.")
    if important_disabled:
        print(f"  ⚠️  {len(important_disabled)} of them matter for this project's analysis: "
              f"{sorted(important_disabled)}")
        print(f"  This is exactly what caused pcap_analysis.py to see opaque 'eth > data' "
              f"frames instead of proper dissection before it started force-enabling them "
              f"per-invocation. Run with --fix to re-enable these in the saved profile.")
    else:
        print("  None of the protocols this project's analysis depends on are disabled — "
              "the real Wireshark GUI should dissect pcaps normally.")
    return important_disabled


def fix(path):
    important_disabled = audit(path)
    if not important_disabled:
        print("\nNothing to fix.")
        return False

    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy(path, backup)
    print(f"\nBacked up original to {backup}")

    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if line.strip() not in IMPORTANT_PROTOCOLS]
    path.write_text("\n".join(kept) + ("\n" if kept else ""), encoding="utf-8")

    print(f"Removed {important_disabled} from {path.name}. "
          f"Restart Wireshark/tshark for the change to take effect.")
    return True


def self_test():
    print("=== Wireshark config audit self-test (temp file only, real profile untouched) ===\n")
    tmp_dir = Path(tempfile.mkdtemp(prefix="pycyber_wsaudit_"))
    fake_disabled_protos = tmp_dir / "disabled_protos"
    # Mirrors the REAL file this machine's profile actually had: a mix of
    # protocols this project cares about and ones it doesn't.
    fake_disabled_protos.write_text("ip\nhttp\ncommunityid\nstcsig\neobi\n", encoding="utf-8")

    print("--- Before fix ---")
    important = audit(fake_disabled_protos)
    audit_ok = set(important) == {"ip", "http"}

    print("\n--- Applying fix ---")
    fix(fake_disabled_protos)

    remaining = fake_disabled_protos.read_text(encoding="utf-8").split()
    fix_ok = "ip" not in remaining and "http" not in remaining and "communityid" in remaining

    shutil.rmtree(tmp_dir, ignore_errors=True)

    passed = audit_ok and fix_ok
    print(f"\n{'Self-test PASSED' if passed else 'Self-test FAILED'} — "
          f"audit correctly found {{ip, http}} and nothing else: {audit_ok}; "
          f"fix removed only those two, left unrelated disabled protocols alone: {fix_ok}.")


def main():
    args = sys.argv[1:]
    if "--self-test" in args:
        self_test()
    elif "--fix" in args:
        fix(REAL_DISABLED_PROTOS_PATH)
    else:
        audit(REAL_DISABLED_PROTOS_PATH)


if __name__ == "__main__":
    main()
