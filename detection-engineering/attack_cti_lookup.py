#!/usr/bin/env python
"""
MITRE ATT&CK CTI validation — depth roadmap. Cross-checks every technique
ID this project claims coverage for (export_navigator_layer.py's
TECHNIQUES list) against MITRE's own official, published STIX dataset —
not a hand-typed guess at what a technique ID means, the actual source of
truth the real ATT&CK Navigator itself is built from. Catches typos,
deprecated IDs, and technique-name drift that a hand-maintained comment
string can silently accumulate over 23 entries added across five phases.

Downloads the official enterprise-attack STIX bundle once (~48MB, cached
locally at detection-engineering/attack-stix/, gitignored — not something
to commit) and queries it with mitreattack-python, the same library the
Center for Threat-Informed Defense publishes for working with this data.

Usage:
    python attack_cti_lookup.py --validate     # cross-check this project's
                                                  # 23 mapped techniques
                                                  # against the real dataset
    python attack_cti_lookup.py --lookup T1486  # look up one technique's
                                                    official name/tactic/
                                                    description
"""
import sys
import urllib.request
from pathlib import Path

from mitreattack.stix20 import MitreAttackData

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from export_navigator_layer import TECHNIQUES  # noqa: E402

STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
CACHE_DIR = Path(__file__).resolve().parent / "attack-stix"
CACHE_FILE = CACHE_DIR / "enterprise-attack.json"


def ensure_stix_data():
    CACHE_DIR.mkdir(exist_ok=True)
    if CACHE_FILE.exists():
        size_mb = CACHE_FILE.stat().st_size / 1e6
        print(f"Using cached STIX bundle: {CACHE_FILE} ({size_mb:.1f} MB)")
        return
    print(f"Downloading the official MITRE ATT&CK STIX bundle from {STIX_URL} ...")
    urllib.request.urlretrieve(STIX_URL, CACHE_FILE)
    size_mb = CACHE_FILE.stat().st_size / 1e6
    print(f"Cached to {CACHE_FILE} ({size_mb:.1f} MB) — future runs reuse this file.")


def load_data():
    ensure_stix_data()
    return MitreAttackData(str(CACHE_FILE))


def validate(mad):
    print(f"\n=== Validating this project's {len(TECHNIQUES)} mapped techniques "
          f"against MITRE's official data ===\n")
    all_valid = True
    for tid, score, comment in TECHNIQUES:
        obj = mad.get_object_by_attack_id(tid, "attack-pattern")
        if obj is None:
            print(f"  ❌ {tid}: NOT FOUND in official MITRE data — typo or deprecated ID?")
            all_valid = False
            continue
        official_name = obj["name"]
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                   if p["kill_chain_name"] == "mitre-attack"]
        flag = "  ⚠️  DEPRECATED" if obj.get("x_mitre_deprecated") else ""
        print(f"  ✓ {tid:12} {official_name:48} [{', '.join(tactics)}]{flag}")

    print(f"\n{'All ' + str(len(TECHNIQUES)) + ' technique IDs are valid, official MITRE ATT&CK technique IDs.' if all_valid else 'Some technique IDs need attention — see ❌ above.'}")
    return all_valid


def lookup(mad, tid):
    obj = mad.get_object_by_attack_id(tid, "attack-pattern")
    if obj is None:
        print(f"{tid} was not found in the official MITRE ATT&CK dataset.")
        return
    tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
               if p["kill_chain_name"] == "mitre-attack"]
    print(f"=== {tid}: {obj['name']} ===\n")
    print(obj.get("description", "")[:600].strip() + "...")
    print(f"\nTactic(s): {', '.join(tactics)}")
    print(f"Deprecated: {obj.get('x_mitre_deprecated', False)}")
    print(f"Platforms: {', '.join(obj.get('x_mitre_platforms', []))}")


def main():
    args = sys.argv[1:]
    mad = load_data()

    if "--validate" in args:
        validate(mad)
    elif "--lookup" in args:
        i = args.index("--lookup")
        lookup(mad, args[i + 1])
    else:
        print("Usage: python attack_cti_lookup.py [--validate | --lookup TECHNIQUE_ID]")


if __name__ == "__main__":
    main()
