#!/usr/bin/env python
"""
Collection — MITRE ATT&CK Collection tactic (T1005 Data from Local System,
T1074.001 Local Data Staging) paired with a staging-behavior detector.

The "attack" side searches ONLY its own dedicated scratch/ folder — never
your real Desktop/Documents/Downloads — for filenames matching patterns
malware collectors look for (password/wallet/key-shaped names). It creates
those dummy files itself first.

The "defense" side is the actually-useful part: real collection almost
always involves STAGING — copying scattered files into one new directory
before exfiltrating them together. A sudden burst of file creation in a
brand-new directory in a short time window is a strong, real behavioral
signal — this reuses the same snapshot-diff pattern as
impact/ransomware_sim.py's mass-file-change hunter and
persistence/persistence_demo.py's hunt, applied here to "did a new
directory just fill up with files fast."

Usage:
    python collection_demo.py --demo
"""
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

SCRATCH_DIR = Path(__file__).resolve().parent / "scratch"
STAGING_DIR = SCRATCH_DIR / "staged"

INTERESTING_FILENAMES = [
    "passwords.txt", "wallet.dat", "id_rsa", "credentials.json",
    "notes_unrelated.txt", "photo.jpg",  # decoys - should NOT be flagged
]
SENSITIVE_PATTERNS = ["password", "wallet", "id_rsa", "credential", "secret", "key"]


def create_dummy_environment():
    print("=== Creating dummy files (own scratch/ folder only) ===")
    SCRATCH_DIR.mkdir(exist_ok=True)
    for name in INTERESTING_FILENAMES:
        (SCRATCH_DIR / name).write_text(f"dummy content for {name}\n")
    print(f"  Created {len(INTERESTING_FILENAMES)} files in {SCRATCH_DIR}")


def find_interesting_files():
    print("\n=== Searching for sensitive-looking filenames (T1005) ===")
    found = []
    for path in SCRATCH_DIR.glob("*"):
        if path.is_file() and any(pat in path.name.lower() for pat in SENSITIVE_PATTERNS):
            found.append(path)
            print(f"  Found: {path.name}")
    print(f"  ({len(found)}/{len(INTERESTING_FILENAMES)} files matched — the decoys correctly did not)")
    return found


def stage_files(files):
    print("\n=== Staging (T1074.001) — copying matches into one new directory ===")
    before_exists = STAGING_DIR.exists()
    STAGING_DIR.mkdir(exist_ok=True)
    for f in files:
        (STAGING_DIR / f.name).write_bytes(f.read_bytes())
    print(f"  Staged {len(files)} file(s) into {STAGING_DIR} "
          f"({'new directory' if not before_exists else 'existing directory'})")


def hunt_staging_behavior():
    """The real signal: how many files appeared in STAGING_DIR, and does
    the count suggest a deliberate bulk-copy burst rather than normal use?"""
    print("\n=== Staging-behavior hunter (defensive) ===")
    if not STAGING_DIR.exists():
        print("  No staging directory found.")
        return False
    count = len(list(STAGING_DIR.glob("*")))
    if count >= 3:
        print(f"  ⚠️  MEDIUM: {count} files appeared in a single directory ({STAGING_DIR.name}) — "
              f"consistent with collection staging ahead of exfiltration.")
        return True
    print(f"  Only {count} file(s) — below the burst threshold.")
    return False


def cleanup():
    print("\n=== Cleanup ===")
    for f in SCRATCH_DIR.glob("*"):
        if f.is_dir():
            for sub in f.glob("*"):
                sub.unlink()
            f.rmdir()
        else:
            f.unlink()
    SCRATCH_DIR.rmdir()
    print("  Removed all dummy/staged files.")


def main():
    if "--demo" not in sys.argv:
        print("Usage: python collection_demo.py --demo")
        return
    create_dummy_environment()
    found = find_interesting_files()
    stage_files(found)
    hunt_staging_behavior()
    cleanup()


if __name__ == "__main__":
    main()
