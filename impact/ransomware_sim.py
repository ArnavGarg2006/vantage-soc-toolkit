#!/usr/bin/env python
"""
Impact — MITRE ATT&CK Impact tactic (T1486 Data Encrypted for Impact)
paired with a real Shield Detect-style mass-file-change hunter, and always
followed by real decryption. This is a simulation of the *behavior*, not a
functional weapon: it only ever touches files it creates itself, inside its
own scratch/ folder, and the AES key is saved to disk specifically so
nothing here can ever be un-recoverable.

Flow, always run in this order by --demo:
  1. Create N dummy files with known content in impact/scratch/
  2. Snapshot the folder (file count, extensions, total size)
  3. "Encrypt" every file with AES-256 (pycryptodomex), save the key
  4. Snapshot again - this diff IS the ransomware behavioral signature
     (mass extension change in a short time window) - the hunter reports it
  5. Decrypt everything back using the saved key
  6. Verify decrypted content matches the original exactly
  7. Clean up - remove scratch files and the key, confirm nothing is left

Usage:
    python ransomware_sim.py --demo
"""
import os
import sys
import time
from collections import Counter
from pathlib import Path

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

SCRATCH_DIR = Path(__file__).parent / "scratch"
KEY_FILE = Path(__file__).parent / "recovery_key.bin"
ENCRYPTED_EXT = ".encrypted"
DUMMY_FILE_COUNT = 6


def create_dummy_files():
    print("=== Creating dummy files (content this script generates) ===")
    SCRATCH_DIR.mkdir(exist_ok=True)
    originals = {}
    for i in range(DUMMY_FILE_COUNT):
        path = SCRATCH_DIR / f"dummy_file_{i}.txt"
        content = f"This is disposable test content for file {i}.\nNothing real is stored here.\n" * 5
        # newline="" disables Windows' \n -> \r\n translation on write, so the
        # on-disk bytes are byte-for-byte what encryption reads back - without
        # this, the later exact-match verification fails on a newline mismatch
        # that has nothing to do with the crypto (which is otherwise correct).
        path.write_text(content, newline="")
        originals[path.name] = content
    print(f"  Created {DUMMY_FILE_COUNT} files in {SCRATCH_DIR}")
    return originals


def snapshot_folder():
    ext_counts = Counter(p.suffix for p in SCRATCH_DIR.iterdir() if p.is_file())
    return dict(ext_counts)


def encrypt_folder():
    print("\n=== Encrypting (AES-256, key saved to disk immediately) ===")
    key = get_random_bytes(32)
    KEY_FILE.write_bytes(key)

    for path in list(SCRATCH_DIR.glob("*.txt")):
        cipher = AES.new(key, AES.MODE_EAX)
        data = path.read_bytes()
        ciphertext, tag = cipher.encrypt_and_digest(data)

        enc_path = path.with_suffix(ENCRYPTED_EXT)
        with open(enc_path, "wb") as f:
            f.write(cipher.nonce)
            f.write(tag)
            f.write(ciphertext)
        path.unlink()

    print(f"  Encrypted {DUMMY_FILE_COUNT} files. Recovery key saved to {KEY_FILE}")


def hunt_mass_file_change(before, after):
    """The actual detection signature: a burst of files changing to the same
    new extension in a short window is THE classic ransomware behavioral
    indicator - this is what real EDR file-monitoring rules look for,
    independent of knowing anything about the specific malware."""
    print("\n=== Mass file-change hunter (behavioral detection) ===")
    print(f"  Before: {before}")
    print(f"  After:  {after}")

    new_ext_count = after.get(ENCRYPTED_EXT, 0)
    if new_ext_count >= DUMMY_FILE_COUNT * 0.8:
        msg = f"{new_ext_count} files changed to '{ENCRYPTED_EXT}' in this pass — mass extension change, ransomware signature"
        print(f"  ⚠️  HIGH: {msg}")
        emit(source="ransomware_sim", technique_id="T1486", severity="HIGH", message=msg)
    else:
        print("  No mass extension-change pattern detected.")


def decrypt_folder():
    print("\n=== Decrypting (recovery) ===")
    if not KEY_FILE.exists():
        print("  No recovery key found — cannot decrypt.")
        return {}
    key = KEY_FILE.read_bytes()

    recovered = {}
    for enc_path in list(SCRATCH_DIR.glob(f"*{ENCRYPTED_EXT}")):
        raw = enc_path.read_bytes()
        nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        out_path = enc_path.with_suffix(".txt")
        out_path.write_bytes(data)
        enc_path.unlink()
        recovered[out_path.name] = data.decode()

    print(f"  Decrypted {len(recovered)} file(s).")
    return recovered


def verify_and_cleanup(originals, recovered):
    print("\n=== Verifying recovery matches original exactly ===")
    all_match = originals == recovered
    print("  MATCH — full recovery confirmed." if all_match else "  MISMATCH — something went wrong!")

    print("\n=== Cleanup ===")
    for p in SCRATCH_DIR.glob("*"):
        p.unlink()
    SCRATCH_DIR.rmdir()
    if KEY_FILE.exists():
        KEY_FILE.unlink()
    print("  Scratch folder and recovery key removed — nothing left behind.")
    return all_match


def run_demo():
    originals = create_dummy_files()
    before = snapshot_folder()

    encrypt_folder()
    time.sleep(0.2)
    after = snapshot_folder()
    hunt_mass_file_change(before, after)

    recovered = decrypt_folder()
    success = verify_and_cleanup(originals, recovered)

    print(f"\n{'PASSED' if success else 'FAILED'}: full encrypt -> detect -> decrypt -> verify -> cleanup cycle.")


def main():
    if "--demo" not in sys.argv:
        print("Usage: python ransomware_sim.py --demo")
        return
    run_demo()


if __name__ == "__main__":
    main()
