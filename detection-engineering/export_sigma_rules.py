#!/usr/bin/env python
"""
Sigma rule export — converts the heuristics in shield-detect/process_monitor.py
into real Sigma rules (https://github.com/SigmaHQ/sigma), the industry-standard
generic detection-rule format that translates into Splunk SPL, Elastic
KQL/EQL, Microsoft Sentinel KQL, and dozens of other SIEM query languages via
the `sigma-cli`/`pySigma` backends.

This is the actual deliverable a detection engineer produces from "I noticed
this pattern" — a portable rule, not a one-off script tied to this project.

Usage:
    python export_sigma_rules.py
"""
import sys
import uuid
from datetime import date
from pathlib import Path

import yaml

sys.stdout.reconfigure(encoding="utf-8")

OUT_DIR = Path(__file__).parent / "sigma-rules"

RULES = [
    {
        "title": "Known LOLBin Process Execution",
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "pycyber-lolbin-execution")),
        "status": "experimental",
        "description": (
            "Detects execution of a binary commonly abused for living-off-the-land "
            "attacks (LOLBins). Matches the heuristic in shield-detect/process_monitor.py."
        ),
        "author": "python-for-cybersecurity project",
        "date": date.today().strftime("%Y/%m/%d"),
        "references": ["https://lolbas-project.github.io/"],
        "tags": ["attack.execution", "attack.t1059", "attack.defense-evasion", "attack.t1218"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "Image|endswith": [
                    "\\powershell.exe", "\\cmd.exe", "\\wscript.exe", "\\cscript.exe",
                    "\\mshta.exe", "\\certutil.exe", "\\regsvr32.exe", "\\rundll32.exe",
                ]
            },
            "condition": "selection",
        },
        "falsepositives": ["Legitimate administrative scripts and scheduled tasks"],
        "level": "medium",
    },
    {
        "title": "Encoded or Obfuscated PowerShell Command Line",
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "pycyber-encoded-powershell")),
        "status": "experimental",
        "description": (
            "Detects PowerShell invoked with an encoded/obfuscated command-line flag "
            "(-enc, -e, -EncodedCommand) — a common technique to hide the actual command "
            "from casual log review. Matches the heuristic in process_monitor.py."
        ),
        "author": "python-for-cybersecurity project",
        "date": date.today().strftime("%Y/%m/%d"),
        "references": ["https://attack.mitre.org/techniques/T1027/"],
        "tags": ["attack.defense-evasion", "attack.t1027", "attack.execution", "attack.t1059.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_image": {"Image|endswith": "\\powershell.exe"},
            "selection_flag": {
                "CommandLine|contains": ["-enc", "-EncodedCommand", " -e "]
            },
            "condition": "selection_image and selection_flag",
        },
        "falsepositives": ["Legitimate scripts that pass base64-encoded arguments"],
        "level": "high",
    },
    {
        "title": "Office Application Spawning a LOLBin",
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "pycyber-office-spawns-lolbin")),
        "status": "experimental",
        "description": (
            "Detects a Microsoft Office application (Word, Excel, Outlook) spawning a "
            "known LOLBin as a child process — the classic macro-malware execution "
            "pattern. Matches the heuristic in process_monitor.py."
        ),
        "author": "python-for-cybersecurity project",
        "date": date.today().strftime("%Y/%m/%d"),
        "references": ["https://attack.mitre.org/techniques/T1566/001/"],
        "tags": ["attack.execution", "attack.t1204.002", "attack.initial-access", "attack.t1566.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection_parent": {
                "ParentImage|endswith": ["\\winword.exe", "\\excel.exe", "\\outlook.exe"]
            },
            "selection_child": {
                "Image|endswith": [
                    "\\powershell.exe", "\\cmd.exe", "\\wscript.exe", "\\cscript.exe",
                    "\\mshta.exe", "\\certutil.exe", "\\regsvr32.exe", "\\rundll32.exe",
                ]
            },
            "condition": "selection_parent and selection_child",
        },
        "falsepositives": ["Rare legitimate document automation workflows"],
        "level": "high",
    },
]


def main():
    OUT_DIR.mkdir(exist_ok=True)
    for rule in RULES:
        filename = rule["title"].lower().replace(" ", "_").replace("-", "") + ".yml"
        path = OUT_DIR / filename
        with open(path, "w", encoding="utf-8") as f:
            yaml.dump(rule, f, sort_keys=False, default_flow_style=False, allow_unicode=True)
        print(f"Wrote {path}")

    print(f"\n{len(RULES)} Sigma rule(s) exported to {OUT_DIR}")
    print("Validating round-trip (parse back what was written)...")
    for path in OUT_DIR.glob("*.yml"):
        with open(path, encoding="utf-8") as f:
            parsed = yaml.safe_load(f)
        assert parsed["title"] and parsed["detection"]["condition"], f"malformed: {path}"
    print("  All rules parse back correctly as valid YAML with required Sigma fields present.")


if __name__ == "__main__":
    main()
