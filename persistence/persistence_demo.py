#!/usr/bin/env python
"""
Persistence — MITRE ATT&CK Persistence tactic (T1547.001 Registry Run Keys)
paired with a real Shield Detect-style "persistence hunter."

Scoping (see project README): this demonstrates the MECHANISM — create,
verify, then immediately remove a Run key pointing at a completely inert
payload — within a single run. It does not force an actual logon cycle, so
it never really executes the payload; that would need you to log off and
back on, which is outside what a script should do to your session. What's
proven here is exactly what a real detector would see: the registry
artifact itself, appearing and disappearing.

Uses only HKEY_CURRENT_USER — no admin privileges needed, and nothing here
touches HKEY_LOCAL_MACHINE or any other user's account.

Usage:
    python persistence_demo.py --demo    # create, verify, remove
    python persistence_demo.py --hunt    # scan real persistence locations
                                          # on this machine (defensive tool,
                                          # safe to run any time)
"""
import argparse
import os
import sys
import winreg

sys.stdout.reconfigure(encoding="utf-8")

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
DEMO_VALUE_NAME = "PyCyberDemo_DO_NOT_LEAVE_RUNNING"
# Deliberately inert: appends one line to a log file in this project folder.
# Never actually gets a chance to run in this demo (see docstring above).
DEMO_PAYLOAD = (
    f'cmd.exe /c echo persistence-demo-executed >> '
    f'"{os.path.join(os.path.dirname(__file__), "demo_log.txt")}"'
)


def create_demo_persistence():
    print("=== Creating demo persistence (HKCU Run key) ===")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, DEMO_VALUE_NAME, 0, winreg.REG_SZ, DEMO_PAYLOAD)
    print(f"  Set HKCU\\{RUN_KEY_PATH}\\{DEMO_VALUE_NAME} = {DEMO_PAYLOAD}")


def verify_demo_persistence():
    print("\n=== Verifying it's actually there ===")
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, DEMO_VALUE_NAME)
        print(f"  Confirmed present: {value}")
        return True
    except FileNotFoundError:
        print("  Not found.")
        return False


def remove_demo_persistence():
    print("\n=== Removing it (cleanup) ===")
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, DEMO_VALUE_NAME)
        print("  Removed.")
    except FileNotFoundError:
        print("  Already gone.")


def run_demo():
    create_demo_persistence()
    verify_demo_persistence()
    remove_demo_persistence()
    still_there = verify_demo_persistence_silent()
    print("\nFinal check:", "STILL PRESENT (cleanup failed!)" if still_there else "confirmed removed, nothing left behind.")


def verify_demo_persistence_silent():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, DEMO_VALUE_NAME)
        return True
    except FileNotFoundError:
        return False


def hunt_persistence():
    """Defensive tool: enumerate real persistence locations on this machine.
    Safe to run any time — read-only, reports what it finds."""
    print("=== Persistence hunter — scanning common autostart locations ===\n")

    print("--- Run / RunOnce keys (HKCU and HKLM) ---")
    for hive, hive_name in [(winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")]:
        for subkey in [r"Software\Microsoft\Windows\CurrentVersion\Run",
                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"]:
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            flag = " ⚠️  demo artifact" if name == DEMO_VALUE_NAME else ""
                            print(f"  {hive_name}\\{subkey}\\{name} = {value}{flag}")
                            i += 1
                        except OSError:
                            break
            except FileNotFoundError:
                continue

    print("\n--- Startup folder ---")
    startup = os.path.join(os.environ.get("APPDATA", ""),
                            r"Microsoft\Windows\Start Menu\Programs\Startup")
    if os.path.isdir(startup):
        entries = os.listdir(startup)
        if entries:
            for e in entries:
                print(f"  {os.path.join(startup, e)}")
        else:
            print("  (empty)")

    print("\n--- Scheduled tasks (user-created, via schtasks) ---")
    import subprocess
    try:
        result = subprocess.run(["schtasks", "/query", "/fo", "csv"],
                                 capture_output=True, text=True, timeout=15)
        lines = [l for l in result.stdout.splitlines()[1:] if l.strip()]
        print(f"  {len(lines)} scheduled task(s) found — run 'schtasks /query /fo list /v' "
              f"for full detail on any that look unfamiliar.")
    except Exception as e:
        print(f"  Could not query scheduled tasks: {e}")


def main():
    parser = argparse.ArgumentParser(description="Persistence technique demo + defensive persistence hunter.")
    parser.add_argument("--demo", action="store_true", help="Create, verify, and remove a demo Run key")
    parser.add_argument("--hunt", action="store_true", help="Scan real persistence locations (defensive)")
    args = parser.parse_args()

    if not args.demo and not args.hunt:
        parser.error("pass --demo or --hunt")

    if args.demo:
        run_demo()
    if args.hunt:
        hunt_persistence()


if __name__ == "__main__":
    main()
