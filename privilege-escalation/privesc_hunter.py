#!/usr/bin/env python
"""
Privilege Escalation hunter — MITRE ATT&CK Privilege Escalation tactic
(T1574.009 Path Interception by Unquoted Path, T1548.002 Bypass User
Account Control via AlwaysInstallElevated).

This is entirely a DEFENSIVE audit tool — same spirit as the AWS audit
project's checks, applied to local Windows misconfigurations. It never
attempts to actually escalate privileges; it only finds and reports the
misconfigurations that a real privesc technique would need to exist.

Uses the `wmi` library (listed as a required dependency in the course
handout, unused until now) for service enumeration.

Checks:
  1. Unquoted service paths — a service binary path with a space and no
     surrounding quotes lets Windows try each space-delimited segment as a
     potential executable, so C:\\Program.exe (planted by an attacker) would
     run before C:\\Program Files\\Vendor\\service.exe if that directory is
     ever user-writable.
  2. AlwaysInstallElevated — if set in BOTH HKCU and HKLM, any user can
     install an MSI package with SYSTEM privileges.
  3. Services running from user-writable-looking locations (%TEMP%,
     %APPDATA%, a user profile directory instead of Program Files/System32).

Usage:
    python privesc_hunter.py
"""
import os
import sys
import winreg

import wmi

sys.stdout.reconfigure(encoding="utf-8")

USER_WRITABLE_HINTS = ["\\appdata\\", "\\temp\\", "\\users\\public\\", "\\downloads\\"]


def check_unquoted_paths(services):
    print("=== Unquoted service paths (T1574.009) ===")
    findings = []
    for svc in services:
        path = (svc.PathName or "").strip()
        if not path or path.startswith('"'):
            continue
        exe_part = path.split(".exe", 1)[0] + ".exe" if ".exe" in path.lower() else path
        if " " in exe_part:
            findings.append((svc.Name, path))

    if not findings:
        print("  None found.")
    else:
        for name, path in findings:
            print(f"  ⚠️  {name}: {path}")
    return findings


def check_always_install_elevated():
    print("\n=== AlwaysInstallElevated (T1548.002) ===")
    hkcu = _read_dword(winreg.HKEY_CURRENT_USER, r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
    hklm = _read_dword(winreg.HKEY_LOCAL_MACHINE, r"Software\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
    print(f"  HKCU: {hkcu}, HKLM: {hklm}")
    if hkcu == 1 and hklm == 1:
        print("  ⚠️  BOTH set to 1 — any user can install MSI packages with SYSTEM privileges.")
        return True
    print("  Not vulnerable (needs both keys set to 1).")
    return False


def _read_dword(hive, path, name):
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except FileNotFoundError:
        return None


def check_writable_service_locations(services):
    print("\n=== Services running from user-writable-looking locations ===")
    findings = []
    for svc in services:
        path = (svc.PathName or "").lower()
        for hint in USER_WRITABLE_HINTS:
            if hint in path:
                findings.append((svc.Name, svc.PathName))
                break

    if not findings:
        print("  None found.")
    else:
        for name, path in findings:
            print(f"  ⚠️  {name}: {path}")
    return findings


def main():
    print("Enumerating Windows services via WMI...\n")
    c = wmi.WMI()
    services = list(c.Win32_Service())
    print(f"({len(services)} services enumerated)\n")

    unquoted = check_unquoted_paths(services)
    elevated = check_always_install_elevated()
    writable = check_writable_service_locations(services)

    total = len(unquoted) + (1 if elevated else 0) + len(writable)
    print(f"\n{total} potential privilege-escalation misconfiguration(s) found "
          f"across {len(services)} services + registry checks.")


if __name__ == "__main__":
    main()
