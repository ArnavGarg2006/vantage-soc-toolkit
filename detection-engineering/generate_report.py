#!/usr/bin/env python
"""
Unified HTML report generator — Phase 5, item 3. One command that actually
re-runs the attack-simulation scorecard and the attack-chain scorecard,
pulls in the current Sigma rule set and ATT&CK Navigator coverage, and
renders all of it into one self-contained HTML file — the kind of
deliverable a real pentest/purple-team engagement hands over at the end,
instead of four separate terminal outputs nobody keeps.

Every number in the report comes from one live pass of this session's real
code — imported and executed via importlib, the same pattern the scorecards
already use for their hyphenated-directory modules. The chain-level section
reuses the SAME Result objects the single-technique run just produced
(rather than re-running each demo a second time) so the whole report comes
from one execution pass, not three.

Usage:
    python generate_report.py
    # writes detection-engineering/security_report.html
"""
import datetime
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scorecard"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from attack_simulation_scorecard import (  # noqa: E402
    run_persistence, run_credential_access, run_c2, run_impact,
)
from attack_chain_scorecard import run_exfiltration_of_harvested_creds  # noqa: E402
from export_navigator_layer import TECHNIQUES  # noqa: E402

import yaml  # noqa: E402

OUT_PATH = Path(__file__).resolve().parent / "security_report.html"
SIGMA_DIR = Path(__file__).resolve().parent / "sigma-rules"


def esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))


def run_all():
    print("Running attack-simulation scorecard (one live pass)...")
    single_results = [run_persistence(), run_credential_access(), run_c2(), run_impact()]
    by_id = {r.attack_id: r for r in single_results}

    print("\nScoring attack chains (reusing the live results above, plus one fresh exfil run)...")
    exfil_result = run_exfiltration_of_harvested_creds()
    chain_a_results = [by_id["T1547.001"], by_id["T1555.003"], exfil_result]
    chain_b_results = [by_id["T1071.001"], by_id["T1486"]]

    chains = [
        {"name": "Credential Theft → Exfiltration", "results": chain_a_results,
         "any": any(r.caught for r in chain_a_results), "full": all(r.caught for r in chain_a_results)},
        {"name": "C2-Driven Ransomware", "results": chain_b_results,
         "any": any(r.caught for r in chain_b_results), "full": all(r.caught for r in chain_b_results)},
    ]

    print("\nReading Sigma rule set...")
    sigma_rules = []
    if SIGMA_DIR.exists():
        for path in sorted(SIGMA_DIR.glob("*.yml")):
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                sigma_rules.append({
                    "file": path.name,
                    "title": data.get("title", path.stem),
                    "description": data.get("description", ""),
                    "level": data.get("level", ""),
                })
            except Exception as e:
                sigma_rules.append({"file": path.name, "title": path.stem, "description": f"(parse error: {e})", "level": ""})

    return single_results, chains, sigma_rules


def render(single_results, chains, sigma_rules):
    caught_count = sum(1 for r in single_results if r.caught)
    techniques_green = sum(1 for _, score, _ in TECHNIQUES if score == 100)

    def sev_row(r):
        cls = "ok" if r.caught else "bad"
        status = "CAUGHT" if r.caught else "MISSED"
        return f"""<tr><td>{esc(r.technique)}</td><td><code>{esc(r.attack_id)}</code></td>
            <td><span class="pill {cls}">{status}</span></td><td>{esc(r.evidence)}</td></tr>"""

    single_rows = "\n".join(sev_row(r) for r in single_results)

    tech_rows = "\n".join(
        f"""<tr><td><code>{esc(tid)}</code></td>
            <td><span class="pill {'ok' if score == 100 else 'warn' if score > 0 else 'bad'}">{score}</span></td>
            <td>{esc(comment)}</td></tr>"""
        for tid, score, comment in TECHNIQUES
    )

    def chain_block(chain):
        stage_rows = "\n".join(
            f"""<li><span class="pill {'ok' if r.caught else 'bad'}">{'CAUGHT' if r.caught else 'MISSED'}</span>
                {esc(r.technique)} (<code>{esc(r.attack_id)}</code>) — {esc(r.evidence)}</li>"""
            for r in chain["results"]
        )
        gap_note = ""
        if chain["any"] and not chain["full"]:
            gap_note = ('<p class="gap-note">⚠️ Partial visibility: at least one stage was caught, '
                        'but not every stage — a defender relying only on this chain\'s coverage would '
                        'be alerted, but not to the full scope of the intrusion.</p>')
        return f"""
        <div class="card">
          <h3>{esc(chain['name'])}</h3>
          <ul class="stage-list">{stage_rows}</ul>
          <div class="chain-metrics">
            <span class="pill {'ok' if chain['any'] else 'bad'}">any_stage_caught: {chain['any']}</span>
            <span class="pill {'ok' if chain['full'] else 'bad'}">full_chain_caught: {chain['full']}</span>
          </div>
          {gap_note}
        </div>"""

    chain_blocks = "\n".join(chain_block(c) for c in chains)

    sigma_rows = "\n".join(
        f"""<tr><td>{esc(s['file'])}</td><td>{esc(s['title'])}</td>
            <td><span class="pill warn">{esc(s['level'] or 'n/a')}</span></td><td>{esc(s['description'])}</td></tr>"""
        for s in sigma_rules
    ) or '<tr><td colspan="4" class="empty">No Sigma rules found — run export_sigma_rules.py first.</td></tr>'

    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Vantage SOC Toolkit — Security Assessment Report</title>
<style>
  body {{ background:#0d1117; color:#c9d1d9; font-family: Consolas, monospace; margin:0; padding:32px; max-width:1100px; }}
  h1 {{ font-size:24px; margin:0 0 4px 0; color:#e6edf3; }}
  h2 {{ font-size:16px; margin:36px 0 12px 0; color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:6px; }}
  h3 {{ font-size:14px; margin:0 0 10px 0; color:#e6edf3; }}
  .sub {{ color:#8b949e; font-size:13px; margin-bottom:24px; }}
  .summary {{ display:flex; gap:16px; flex-wrap:wrap; margin-bottom:8px; }}
  .stat {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:14px 20px; min-width:140px; }}
  .stat .n {{ font-size:26px; font-weight:700; color:#58a6ff; }}
  .stat .l {{ font-size:11px; color:#8b949e; text-transform:uppercase; margin-top:4px; }}
  table {{ width:100%; border-collapse:collapse; margin-bottom:8px; }}
  th {{ text-align:left; padding:8px 10px; border-bottom:1px solid #30363d; color:#8b949e; font-size:11px; text-transform:uppercase; }}
  td {{ padding:8px 10px; border-bottom:1px solid #21262d; font-size:13px; vertical-align:top; }}
  tr:hover td {{ background:#161b22; }}
  code {{ color:#79c0ff; }}
  .pill {{ font-weight:700; padding:2px 8px; border-radius:4px; font-size:11px; display:inline-block; white-space:nowrap; }}
  .pill.ok {{ background:#8ec84322; color:#8ec843; border:1px solid #8ec84355; }}
  .pill.bad {{ background:#ff5c5c22; color:#ff5c5c; border:1px solid #ff5c5c55; }}
  .pill.warn {{ background:#ffb84d22; color:#ffb84d; border:1px solid #ffb84d55; }}
  .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px 20px; margin-bottom:16px; }}
  .stage-list {{ list-style:none; margin:0; padding:0; }}
  .stage-list li {{ padding:6px 0; font-size:13px; border-bottom:1px solid #21262d; }}
  .stage-list li:last-child {{ border-bottom:none; }}
  .chain-metrics {{ margin-top:12px; display:flex; gap:8px; }}
  .gap-note {{ margin-top:12px; font-size:12px; color:#ffb84d; background:#ffb84d11; border:1px solid #ffb84d33; padding:10px 12px; border-radius:6px; }}
  .empty {{ color:#8b949e; text-align:center; }}
  footer {{ margin-top:40px; color:#8b949e; font-size:11px; border-top:1px solid #30363d; padding-top:16px; }}
</style></head>
<body>
  <h1>Vantage SOC Toolkit — Security Assessment Report</h1>
  <div class="sub">Generated {generated} — every number below is from one live execution pass of this project's real code, not a static template.</div>

  <div class="summary">
    <div class="stat"><div class="n">{len(TECHNIQUES)}</div><div class="l">Techniques mapped</div></div>
    <div class="stat"><div class="n">{techniques_green}/{len(TECHNIQUES)}</div><div class="l">Fully verified (green)</div></div>
    <div class="stat"><div class="n">{caught_count}/{len(single_results)}</div><div class="l">Scorecard: caught</div></div>
    <div class="stat"><div class="n">{sum(1 for c in chains if c['full'])}/{len(chains)}</div><div class="l">Chains: full visibility</div></div>
    <div class="stat"><div class="n">{len(sigma_rules)}</div><div class="l">Sigma rules exported</div></div>
  </div>

  <h2>Attack-Simulation Scorecard</h2>
  <table>
    <thead><tr><th>Technique</th><th>ATT&amp;CK ID</th><th>Result</th><th>Evidence</th></tr></thead>
    <tbody>{single_rows}</tbody>
  </table>

  <h2>Attack-Chain Scorecard</h2>
  {chain_blocks}

  <h2>ATT&amp;CK Navigator Coverage</h2>
  <table>
    <thead><tr><th>Technique ID</th><th>Score</th><th>Comment</th></tr></thead>
    <tbody>{tech_rows}</tbody>
  </table>

  <h2>Sigma Detection Rules</h2>
  <table>
    <thead><tr><th>File</th><th>Title</th><th>Level</th><th>Description</th></tr></thead>
    <tbody>{sigma_rows}</tbody>
  </table>

  <footer>
    Vantage SOC Toolkit — generated by detection-engineering/generate_report.py.
    Chain-level results reuse the same live Result objects the scorecard section produced above
    (one execution pass), plus one fresh exfiltration run to score Chain A's third stage.
  </footer>
</body></html>"""


def main():
    single_results, chains, sigma_rules = run_all()
    html = render(single_results, chains, sigma_rules)
    OUT_PATH.write_text(html, encoding="utf-8")
    print(f"\nWrote {OUT_PATH}")
    print(f"{len(single_results)} scorecard results, {len(chains)} chains, "
          f"{len(TECHNIQUES)} techniques, {len(sigma_rules)} Sigma rules.")


if __name__ == "__main__":
    main()
