<div align="center">

# 🎯 Vantage SOC Toolkit

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&size=18&pause=1200&color=A78BFA&center=true&vCenter=true&width=680&lines=24+MITRE+ATT%26CK%2FShield+techniques%2C+each+verified+live.;Real+bugs+found+and+fixed%2C+not+papered+over.;One+event+bus%2C+22+detectors%2C+alerts+that+become+cases.;python+verify_all.py+-+22+passed%2C+0+failed%2C+nothing+hidden.;Sandboxed%2C+reversible%2C+localhost-only+-+never+real+data.)](https://github.com/ArnavGarg2006/vantage-soc-toolkit)

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python&logoColor=white)
![Windows](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)
![ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK_aligned-7F5AF0)
![Shield](https://img.shields.io/badge/MITRE-Shield_aligned-2CB67D)
![Sandboxed](https://img.shields.io/badge/execution-sandboxed_%26_reversible-FF9900)

A portfolio of Python security tooling organized around the **MITRE ATT&CK** (offensive
tactics) and **MITRE Shield** (defensive tactics) frameworks — inspired by the structure
of Howard Poston's [Python for Cybersecurity](https://github.com/hposton/python-for-cybersecurity)
course, not a clone of its code. Every script here is real and independently verified live
(see each module's section below), not a template with placeholder output.

</div>

<br>

<div align="center">
  <img src=".github/assets/verification-matrix.svg" alt="Animated diagram: a grid of 33 module cells filling in one by one, green for passed and amber for blocked, with live counters ticking up to 22 passed, 0 failed, 11 blocked" width="100%">
  <br>
  <sub><b>One command runs the whole project and reports what actually happened.</b> 22 passed, 0 failed, 11 blocked — and <i>blocked is never counted as passing</i>.</sub>
</div>

<br>

<div align="center">
  <img src=".github/assets/dashboard-heartbeat.svg" alt="Animated diagram: an EKG-style waveform scrolling past a fixed 'now' playhead on the live event bus dashboard with alert blips lighting up as they cross it, above a four-stage strip showing an alert travelling from detector to bus to auto-triage to a closed case" width="100%">
  <br>
  <sub>22 detector modules, one shared bus — and since this phase, every alert on it has a lifecycle instead of just a row.</sub>
</div>

<br>

<div align="center">
  <img src=".github/assets/tactic-radial.svg" alt="Animated diagram: a radial progress ring building up segment by segment around 8 ATT&CK/Shield tactic buckets, ending on a center readout of 24 techniques verified, beside a panel listing the YARA, case-management and SOAR response layer" width="100%">
  <br>
  <sub>24 verified techniques spanning the full ATT&CK/Shield chain — plus a response layer on top of them, deliberately not counted as more techniques.</sub>
</div>

<br>

Kept deliberately separate from [`aws security audit`](../aws%20security%20audit/) — that
repo is a focused AWS cloud-security-posture portfolio piece; this one is host/network-level
tooling. Mixing the two would dilute both.

## Safety scoping — read this before running anything

This isn't a legal disclaimer glued on after the fact; it's the actual design constraint
every module was built under:

- **Reconnaissance/Discovery only touch what you own.** DNS recon defaults to `example.com`
  (IANA's RFC 2606-reserved test domain — no real organization behind it). The LAN sweep
  only reaches devices on *your own* directly-connected network segment; it cannot cross
  the internet or reach anything you don't already have physical/logical access to.
- **Nothing here is persistent.** No scheduled tasks, registry Run keys, services, or
  startup entries get created. Nothing survives a script exiting.
- **Nothing here is destructive.** Detection is observe-only — `process_monitor.py` never
  kills or blocks a process, it only reports.
- **Later phases (Persistence, Credential Access, C2, Impact) will be sandboxed the same
  way**: contained to a throwaway scratch folder, localhost-only where networking is
  involved, and — for anything encryption/"impact"-flavored — always reversible, only
  ever touching files created by the demo itself.

## Proof — one command, every module, honest accounting

Everything below this line is a claim. [`verify_all.py`](verify_all.py) is how
you check it without taking my word for anything:

```bash
pip install -r requirements.txt
python verify_all.py              # run everything, print a report
python verify_all.py --quick      # skip the slow network-dependent modules
python verify_all.py --json       # machine-readable
python verify_all.py --only soar  # one area at a time
```

This project has always claimed "verified live, not assumed," and until this
harness existed that claim lived in README prose describing runs nobody else
could reproduce. The difference between a README that *says* the modules work
and a command that *demonstrates* it is the whole point.

### The three verdicts, and why they stay separate

| Verdict | Meaning |
|---|---|
| **PASS** | The module ran and reported success by its own criteria |
| **FAIL** | The module ran and reported failure — a real bug, never a skip |
| **BLOCKED** | It could not run here, with the **specific** missing requirement named: a Windows API, an external binary, admin rights, or outbound network |

**BLOCKED is never counted as success.** Collapsing it into either of the other
two is exactly how coverage numbers become dishonest. A large part of this
project is Windows-only by design (`winreg`, `pywin32`, `netsh`, `arp`,
`powershell`), so on Linux a substantial share legitimately cannot execute — and
the harness prints precisely which parts and why, rather than quietly reporting
a smaller, greener total. Run it on Windows and those same rows become real
PASS/FAIL results.

### Current numbers

Last full run — **Linux, Python 3.11.15, 33 modules, 33.0s**:

| | Count |
|---|---|
| **Passed** | **22** |
| **Failed** | **0** |
| Blocked — Windows-only API | 6 |
| Blocked — outbound network | 3 |
| Blocked — missing binary (`arp`, `tshark`) | 2 |
| **Total modules** | **33** |

**22/22 of everything runnable on this platform passed (100%).** The 11 blocked
are itemized individually in the output, never aggregated away.

| Also verified | Count |
|---|---|
| Detector modules wired to the event bus | 22 |
| ATT&CK techniques in the Navigator layer | 24 |
| YARA rules (each vs. a true positive **and** a benign control) | 5 |
| Sigma rules (round-trip validated) | 3 |
| SOAR playbooks | 3 |
| Self-test assertions in the three newest modules | 21 |

### What this harness does *not* prove

Stated plainly, because a verification tool that oversells itself is worse than
none:

- **It is not a unit-test suite.** Each check runs the module's own `--self-test`
  or `--demo` — the same thing a human would run by hand. The harness adds
  reproducibility and honest accounting, not a new notion of correctness.
- **A module's self-test is only as good as its assertions.** `honeytoken_watcher`
  passed its own self-test on Windows for weeks while being fundamentally broken
  (see below) — the test was real, the assertion just happened to be satisfied by
  timing luck.
- **Blocked rows are genuinely unverified here.** 11 of 33 modules have not been
  run in the environment these numbers come from. That is why they are counted
  separately and why the Windows-only ones are named.

### A bug this found, worth stating on its own

Running the suite on a second platform caught a real defect in
`shield-legitimize/honeytoken_watcher.py`. Its watch loop reassigned the process
baseline on every poll iteration, so each new PID was inspected exactly once —
during the single 0.1s tick in which it first appeared. That is almost always
too early: a process has to finish starting before it opens anything, and a real
attacker's process reads a credential file some time *after* it spawns, not
within the same 100ms.

**The detector was missing essentially every access it was built to catch**, and
only ever passed because process-startup timing on Windows happened to land
inside a poll tick. On Linux the timing stopped being kind and it failed
outright. Fixed so the baseline stays fixed and every new PID stays under
observation for the whole window; verified across three consecutive runs.

That is the argument for this harness in one example: the bug was not found by
reading the code, and not by the self-test that already existed. It was found by
running everything, somewhere else.

## Phase 1 — built and verified

| Module | ATT&CK/Shield mapping | What it does |
|---|---|---|
| [`reconnaissance/dns_recon.py`](reconnaissance/dns_recon.py) | ATT&CK Reconnaissance (T1590.002, T1596.001) | DNS record enumeration, zone-transfer attempt (should always fail — that's the point), subdomain enumeration |
| [`discovery/local_discovery.py`](discovery/local_discovery.py) | ATT&CK Discovery (T1082, T1057, T1016, T1018) | System info, process list, network config, own-LAN ARP sweep |
| [`shield-collect/packet_capture.py`](shield-collect/packet_capture.py) | Shield Collect (DTE0002) | Live packet capture via Npcap/scapy, writes a `.pcap`, protocol + top-talker summary |
| [`shield-collect/pcap_analysis.py`](shield-collect/pcap_analysis.py) | Shield Collect → Detect | Hands a `.pcap` to **tshark** (Wireshark's engine) for protocol hierarchy, conversations, DNS queries, TLS SNI, cleartext HTTP, and a suspicious-indicators pass (cleartext auth, FTP/Telnet, ARP-spoofing signatures); `--open-wireshark` launches the GUI on the file |
| [`shield-collect/correlate_connections.py`](shield-collect/correlate_connections.py) | Discovery → Collect | Resolves a domain/IP and finds which *process* currently holds a connection to it — closes the gap a packet capture alone can't: it shows traffic, not the process behind it |
| [`shield-detect/process_monitor.py`](shield-detect/process_monitor.py) | Shield Detect + Collect fused | Polls for newly-spawned processes, flags LOLBins/encoded PowerShell/suspicious paths/Office-spawns-PowerShell — then checks each flagged process's **live network connections** and escalates to HIGH if it's talking to an external IP. Process behavior + network behavior together is stronger evidence than either alone, and it's the correlation a packet capture by itself can't attribute to a process. |

### Verified output (this machine, this session)

**DNS recon** against `example.com`: resolved A/AAAA/MX/NS/TXT/SOA records, zone transfer
correctly rejected (`FORMERR`), found `www.example.com` via subdomain enumeration.

**Local discovery** with `--scan-lan`: correctly identified the real Wi-Fi subnet
(filtering out four `169.254.x.x` link-local/APIPA adapters that would have produced a
useless scan target — a real bug caught by actually running it, not just reading the code)
and found 10 live devices on the home network via ARP.

**Packet capture**: `python packet_capture.py 5` captured 63 real packets in 5 seconds —
35 TCP, 21 UDP, 3 ARP, 2 ICMP — written to a real `.pcap`, with a top-talkers breakdown.

**tshark analysis** of a fresh capture caught two real, non-obvious things: DNS queries to
`api.bitcore.io` and `api.blockcypher.com` (blockchain APIs) that `correlate_connections.py`
traced to a live `msedge.exe` connection — a browser tab, not a hidden process, but only
knowable by combining capture + process data.

**Correction, found much later while testing against a real downloaded training pcap
(see the depth-roadmap section below)**: this section originally claimed most TCP/UDP
frames showing as opaque `eth > data` instead of properly dissected IP was "a known
effect of NIC hardware checksum/segmentation offload." That explanation was wrong — it
sounded plausible and was never actually verified. The real cause: this machine's
Wireshark profile had the `ip` and `http` dissectors explicitly disabled in
`%APPDATA%\Wireshark\disabled_protos`, global config state with nothing to do with NIC
offload or live capture at all — proven by the fact a completely unrelated, previously
downloaded pcap from another machine showed the identical symptom. `pcap_analysis.py`
now passes `--enable-protocol` on every tshark invocation so it no longer depends on
this machine's ambient Wireshark configuration. Left this correction in place rather
than quietly editing the original claim — the wrong explanation was real output from an
earlier verification pass, and un-verifying a plausible-sounding guess is worth
recording the same way a bug fix is.

**Process monitor self-test**: `python process_monitor.py --self-test` spawns a real
`powershell.exe` child process that opens a real TCP connection to `example.com:80` and
holds it open for 3s. The detector flags the process as a known LOLBin (MEDIUM), then
catches the live connection mid-flight and escalates to a combined-signal HIGH finding —
both halves verified in the same run, not just that the code compiles.

## Usage

```bash
pip install -r requirements.txt

python reconnaissance/dns_recon.py [domain]              # defaults to example.com
python discovery/local_discovery.py [--scan-lan]
python shield-collect/packet_capture.py [seconds] [interface]   # needs admin terminal
python shield-collect/pcap_analysis.py [file.pcap]               # defaults to most recent capture
python shield-collect/pcap_analysis.py --open-wireshark [file]   # also opens the GUI
python shield-collect/correlate_connections.py --domains d1,d2
python shield-collect/correlate_connections.py --ip 1.2.3.4
python shield-detect/process_monitor.py [seconds]
python shield-detect/process_monitor.py --self-test
```

`pcap_analysis.py` and `--open-wireshark` need Wireshark/`tshark` installed
(default path assumed: `C:\Program Files\Wireshark\`).

Packet capture needs an elevated (administrator) terminal for raw socket access on Windows,
and requires [Npcap](https://npcap.com/) installed (already present on this machine).

## Phase 2 — the offensive tactics, sandboxed as promised, built and verified

Each pairs an ATT&CK technique demo with a real Shield-side detector — the same
red+blue pairing the course itself teaches, not offense in isolation.

| Module | ATT&CK/Shield mapping | What it does |
|---|---|---|
| [`persistence/persistence_demo.py`](persistence/persistence_demo.py) | ATT&CK Persistence (T1547.001) | `--demo`: creates an HKCU Run key pointing at an inert payload, verifies it, removes it — all in one run, never triggers an actual logon. `--hunt`: a real defensive tool — enumerates Run/RunOnce keys (HKCU+HKLM), the Startup folder, and scheduled tasks on this machine |
| [`credential-access/credential_access_demo.py`](credential-access/credential_access_demo.py) | ATT&CK Credential Access (T1555.003) | `--demo`: creates its own dummy SQLite "credential store" with fake data and demonstrates the query technique — never touches real saved passwords. `--hunt`: real defensive check — does this machine's actual Chrome/Edge `Login Data` exist, and which process currently holds it open (flags anything that isn't the browser itself) |
| [`c2/beacon_demo.py`](c2/beacon_demo.py) | ATT&CK C2 (T1071.001) | Localhost-only (`127.0.0.1`, never `0.0.0.0`) HTTP server + beacon client in one process, then runs the same **timing-regularity statistics** real tools like RITA/Zeek use to detect beaconing — coefficient of variation on inter-arrival times |
| [`impact/ransomware_sim.py`](impact/ransomware_sim.py) | ATT&CK Impact (T1486) | Creates dummy files in its own `scratch/`, AES-256 encrypts them, runs a **mass-extension-change hunter** (the actual ransomware behavioral signature, independent of knowing the specific malware), then decrypts, verifies byte-for-byte recovery, and deletes everything — key included |

### Verified output — Phase 2

**Persistence**: created the demo Run key, `--hunt` correctly flagged it (`⚠️ demo artifact`)
sitting among this machine's real legitimate autostart entries (OneDrive, Steam, Discord,
etc. — a genuinely useful side effect: a real inventory of what autostarts here), then
removed it with confirmed final state.

**Credential Access**: dummy store created and harvested (3 fake entries, clearly fake).
`--hunt` found the real Chrome and Edge `Login Data` files — Chrome's had no open handles,
Edge's was correctly attributed to `msedge.exe` itself (not flagged, since that's expected).

**C2 beacon**: 8 beacons at a 1.5s interval produced a coefficient of variation of **0.007**
— the detector correctly flagged this as HIGH (threshold 0.15), a textbook beaconing signature.

**Impact**: full cycle passed — 6 dummy files created, encrypted, hunter caught the mass
`.txt` → `.encrypted` change, decrypted, verified byte-for-byte identical to the originals,
scratch folder and key deleted. **Caught a real bug along the way**: the first run failed
verification — not a crypto bug (AES-EAX's own tag check would have thrown), but Windows
translating `\n` → `\r\n` on text write, so the on-disk bytes never matched the in-memory
string being compared against. Fixed with `newline=""` on write.

## Usage — Phase 2

```bash
python persistence/persistence_demo.py --demo
python persistence/persistence_demo.py --hunt

python credential-access/credential_access_demo.py --demo
python credential-access/credential_access_demo.py --hunt

python c2/beacon_demo.py

python impact/ransomware_sim.py --demo
```

## Phase 3 — the roadmap, closed out

| Module | What it does |
|---|---|
| [`shield-contain-disrupt/contain_disrupt_demo.py`](shield-contain-disrupt/contain_disrupt_demo.py) | Shield Contain (DTE0011) + Disrupt (DTE0021). `--process`: spawns its own demo process, suspends it (contain, reversible — verified via resume), then terminates it (disrupt) — never touches a real user process. `--network`: adds/verifies/removes a Windows Firewall rule blocking outbound to `203.0.113.0/24` (RFC 5737 TEST-NET-3, a documentation-only range — needs an elevated terminal) |
| [`scorecard/attack_simulation_scorecard.py`](scorecard/attack_simulation_scorecard.py) | The purple-team piece: imports and re-runs each Phase 2 demo for real, captures the paired detector's actual output, and reports CAUGHT/MISSED per technique — not a hardcoded table |
| [`detection-engineering/export_sigma_rules.py`](detection-engineering/export_sigma_rules.py) | Exports `process_monitor.py`'s 3 heuristics as real [Sigma](https://github.com/SigmaHQ/sigma) rules — the portable format that compiles to Splunk/Elastic/Sentinel queries |
| [`detection-engineering/export_navigator_layer.py`](detection-engineering/export_navigator_layer.py) | Generates a real [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer JSON from this project's actual verified coverage — import it and see the real matrix |
| [`packaging/`](packaging/) | `persistence_demo.py` packaged as a standalone `persistence-hunter.exe` via PyInstaller — runs without Python installed |

### Verified output — Phase 3

**Contain/Disrupt**: spawned a demo PowerShell sleep loop, suspended it (status confirmed
`stopped`), resumed it (confirmed `running` again — containment is reversible), then
terminated it. Network disruption correctly requires elevation and fails cleanly without
leaving a partial firewall rule when run unprivileged.

**Scorecard**: re-ran all four Phase 2 demos live. Result: **3/4 CAUGHT**
(Persistence, C2, Impact) — the one MISS (Credential Access) is an honest, explained gap:
`hunt_credential_access()`'s cross-process detection genuinely works (already proven
against real Chrome/Edge files), but a same-process self-harvest doesn't trigger it —
correctly, since a real detector shouldn't flag a process reading data it created itself.
The actual signal worth watching for is a *different* process reading someone else's
credential store, which the hunter already catches.

**Sigma export**: 3 rules generated and round-trip-validated as parseable YAML with all
required Sigma fields present.

**Navigator export**: 13 techniques mapped with real scores/comments reflecting actual
verified results in this project, JSON round-trip validated.

**PyInstaller**: built `persistence-hunter.exe` (8.9MB, one file), then actually ran the
compiled binary standalone — it enumerated this machine's real autostart entries
identically to the Python source, with no Python installation invoked.

## Usage — Phase 3

```bash
python shield-contain-disrupt/contain_disrupt_demo.py --process
python shield-contain-disrupt/contain_disrupt_demo.py --network   # needs elevated terminal

python scorecard/attack_simulation_scorecard.py

python detection-engineering/export_sigma_rules.py
python detection-engineering/export_navigator_layer.py

cd packaging
pyinstaller --onefile --name persistence-hunter --distpath dist --workpath build --specpath . ../persistence/persistence_demo.py
dist/persistence-hunter.exe --hunt
```

## Phase 4 — closing the honest gaps + the rest of the tactic list

Phase 3 ended with three explicitly-named open items. This phase closes all three:
the Credential Access detector gap, an honest attempt (and write-up) of the
Contain/Disrupt elevation blocker, and every remaining ATT&CK/Shield tactic.

### Credential Access — the gap is closed

`credential_access_demo.py` gained a `--demo-realistic` mode, and two real bugs had to
be found and fixed to make it actually work — not just added and assumed correct:

1. **Path-resolution bug**: `DUMMY_DB` was built from `Path(__file__).parent`, which can
   be relative depending on how the script gets invoked, while `psutil.open_files()`
   always returns absolute paths — so the equality check silently never matched, no
   matter how long the watch window ran. Fixed with `.resolve()` on both sides.
2. **Performance bug, the more interesting one**: even after the path fix, detection
   still didn't fire with real timing margins. Instrumented it and measured a full
   `psutil.process_iter()` + `.open_files()` pass at **12.71 seconds across ~300
   processes** — slower than the entire watch window. This isn't a race to paper over
   with a longer sleep; blind full-system polling is architecturally too slow to catch a
   file held open for a few seconds. It's also *why real EDR products use kernel-level
   filesystem minifilter drivers or ETW instead of user-mode polling* — this project hit
   the actual reason those exist. The realistic fix: `watch_dummy_store()` now takes a
   `target_pid` and checks that one specific process directly (<10ms), which mirrors the
   real SOC workflow — you already have a PID under suspicion (from `process_monitor.py`
   flagging it), you don't blind-scan the whole machine for it.

**Verified**: `python credential_access_demo.py --demo-realistic` spawns the harvest in
a genuinely separate process, and the targeted-PID watch catches it — `⚠️ HIGH: PID
<n> (python.exe) has the credential store open and is not the process that created it.`
Re-running the scorecard after the fix: **4/4 CAUGHT** (previously 3/4, with Credential
Access the one MISS).

### Contain/Disrupt — network half, honestly blocked

Actually attempted `--network` again from this session to see if anything had changed:
it still fails cleanly with a "requires elevation" error adding the Windows Firewall
rule, and leaves no partial rule behind either way. This genuinely cannot be completed
from a non-interactive tool session — UAC elevation requires an interactive prompt this
session cannot answer. To verify it yourself:

```bash
# from an elevated (Run as Administrator) terminal:
python shield-contain-disrupt/contain_disrupt_demo.py --network
```

### The rest of the tactic list — 9 new modules, all built and verified

| Module | ATT&CK/Shield mapping | What it does |
|---|---|---|
| [`privilege-escalation/privesc_hunter.py`](privilege-escalation/privesc_hunter.py) | Privilege Escalation (T1574.009, T1548.002) | Defensive audit via `wmi`: unquoted service paths, `AlwaysInstallElevated` (HKCU+HKLM), services running from user-writable-looking locations |
| [`defense-evasion/masquerade_detector.py`](defense-evasion/masquerade_detector.py) | Defense Evasion (T1036.005) | Flags processes named like well-known system binaries but running from the wrong location; self-test launches a renamed `python.exe` as `svchost.exe` from `%TEMP%` |
| [`lateral-movement/lan_attack_surface.py`](lateral-movement/lan_attack_surface.py) | Lateral Movement (T1021) | ARP-sweeps your own LAN, then TCP-connect-probes SSH/RDP/SMB/WinRM/RPC on each live host — "what's my actual exposure," own-LAN-only |
| [`resource-development/domain_age_checker.py`](resource-development/domain_age_checker.py) | Resource Development (T1583.001) | Public WHOIS lookup, flags domains registered within the last 30 days |
| [`initial-access/phishing_url_analyzer.py`](initial-access/phishing_url_analyzer.py) | Initial Access (T1566) | Pure defensive URL analysis — never sends anything: typosquat detection via edit distance, suspicious TLDs, URL shorteners, raw IPs, `@`-trick, subdomain/hyphen nesting |
| [`collection/collection_demo.py`](collection/collection_demo.py) | Collection (T1005, T1074.001) | Creates dummy sensitive-looking files in its own scratch dir, finds them by name pattern, stages them into one directory, then a staging-burst hunter flags ≥3 files landing in a new directory fast |
| [`exfiltration/exfil_demo.py`](exfiltration/exfil_demo.py) | Exfiltration (T1041) | Localhost-only client/server pair; server-side is a real DLP-style inspector regex-matching card-number-shaped and SSN-shaped patterns in outbound POST bodies — payload data is deliberately Luhn-invalid/fake |
| [`shield-legitimize/honeytoken_watcher.py`](shield-legitimize/honeytoken_watcher.py) | Shield Legitimize (DTE0013) | Deploys a decoy credential file, watches newly-spawned processes for any access at all — a honeytoken has exactly one legitimate reader: nobody |
| [`shield-channel-facilitate/honeypot_listener.py`](shield-channel-facilitate/honeypot_listener.py) | Shield Channel (DTE0004) + Facilitate (DTE0007) | Minimal TCP listener on an unused port (2222) that logs every connection and payload byte — a honeypot's entire job is to BE the observed resource |

**Shield "Test" isn't a separate module** — the self-test pattern used in nearly every
module throughout this whole project (spawn a real process/connection/file access and
prove the detector actually fires, not just that the code compiles) *is* Shield Test in
practice. A dedicated module would just be redundant with what's already everywhere.

### Verified output — Phase 4

**Privilege Escalation**: enumerated real Windows services via `wmi`, found a genuine
unquoted-path finding on this machine (McAfee WebAdvisor), `AlwaysInstallElevated`
correctly reported not-vulnerable (needs both hives set).

**Defense Evasion**: self-test copied `python.exe` to `%TEMP%\svchost.exe`, launched it,
and the scanner correctly flagged it — `⚠️ HIGH: PID <n> named 'svchost.exe' running
from '...\Temp\...\svchost.exe' — not one of ['c:\windows\system32', ...]`. Temp copy
cleaned up after.

**Lateral Movement**: swept the real home LAN — 8 live hosts found, this machine
correctly identified as exposing SMB (445) and RPC (135); no other host on the network
exposed any of the checked ports.

**Resource Development**: WHOIS lookups against `example.com` and `google.com` both
resolved real registration dates, both correctly reported as older than the 30-day
threshold (no false positive on long-established domains).

**Initial Access**: analyzed `www.paypa1.com`, `192.168.1.1`, and a `bit.ly` shortener.
**Found and fixed a real bug**: typosquat detection compared the full host (with `www.`
prefix) against the brand list, so the prefix alone added more edit distance than the
typosquat itself — `www.paypa1.com` never got close enough to `paypal.com` to trip the
threshold. Fixed by stripping `www.` before comparison; re-verified `www.paypa1.com` is
now correctly flagged at edit distance 1 from `paypal.com`.

**Collection**: created 6 dummy files (4 sensitive-named, 2 decoys) — the finder matched
exactly the 4 sensitive ones and correctly ignored both decoys (`photo.jpg`,
`notes_unrelated.txt`). Staging hunter correctly flagged the 4-file burst into a new
directory as `⚠️ MEDIUM`.

**Exfiltration**: client posted the fake payload to the localhost DLP server; both the
card-shaped and SSN-shaped patterns were caught in the same pass.

**Shield Legitimize**: deployed the honeytoken, spawned a separate process to read it.
**Found and fixed a real bug**: the self-test's `open(path).read()` was never bound to a
variable, so CPython garbage-collected the file object (closing the handle) almost
immediately — before the watcher's poll loop could ever observe it open. Fixed by
binding to a variable and holding it open across the sleep before explicit `close()`.
Re-verified PASSED after the fix.

**Shield Channel/Facilitate**: self-test connected to the honeypot listener as a fake
"attacker" sending an SSH-banner-shaped probe string; the connection and payload were
both logged, 1/1 connections caught.

**Navigator export**: re-ran with all 9 new techniques added — now **22 techniques**
mapped (was 13), JSON round-trip validated.

> Since this run the layer has grown to **24 techniques** — the generated
> `attack_navigator_layer.json` is the authoritative count, and it had drifted
> ahead of this prose until a later pass caught it. Left the original figure
> here rather than silently editing it: this section records what one specific
> run produced, and a number that was true then is not made false by later work.

## Usage — Phase 4

```bash
python privilege-escalation/privesc_hunter.py

python defense-evasion/masquerade_detector.py
python defense-evasion/masquerade_detector.py --self-test

python lateral-movement/lan_attack_surface.py

python resource-development/domain_age_checker.py [domain ...]

python initial-access/phishing_url_analyzer.py [url ...]

python collection/collection_demo.py --demo

python exfiltration/exfil_demo.py

python shield-legitimize/honeytoken_watcher.py --self-test

python shield-channel-facilitate/honeypot_listener.py --self-test

python credential-access/credential_access_demo.py --demo-realistic
```

## Phase 5 — pulling 22 separate scripts into one pane of glass (in progress)

Every module through Phase 4 works, but each one only ever printed its own alerts
to its own terminal — there was no single place that showed what the whole project
was catching at once. That's the specific gap Phase 5 closes, one piece at a time.

### Central event bus + live dashboard — built and verified

| Module | What it does |
|---|---|
| [`event-bus/collector.py`](event-bus/collector.py) | Localhost-only (`127.0.0.1:8790`) HTTP collector — any detector can POST an alert to it. Serves a live, auto-refreshing dashboard at `/dashboard` (polls `/events.json` every 2s), and persists every event to a durable SQLite database (`event-bus/events.db`) — not just a flat log |
| [`event_bus_client.py`](event_bus_client.py) | The shared `emit(source, technique_id, severity, message)` client every detector imports. Lives at the project root (not inside `event-bus/`) specifically because a hyphenated directory name can't be `import`ed as a package — the same constraint the scorecard already worked around with `importlib.util` for the Phase 2 modules. Fails silently in ~0.4s if no collector is running: this is strictly additive telemetry, never a dependency of the detection logic itself |
| [`event-bus/query_history.py`](event-bus/query_history.py) | The analysis half of the durable store — a read-only CLI answering questions a live dashboard can't: which technique fires most on this machine, how many HIGH alerts happened this week, the day-by-day trend |

**15 detector modules wired in** at their actual alert points (since grown to
**22** — `grep -rl "from event_bus_client import emit"` is the live count) — every module from
Phase 1 through Phase 4 that produces a real finding: `process_monitor`,
`credential_access_demo`, `beacon_demo`, `ransomware_sim`, `persistence_demo`,
`privesc_hunter`, `masquerade_detector`, `lan_attack_surface`, `domain_age_checker`,
`phishing_url_analyzer`, `collection_demo`, `exfil_demo`, `honeytoken_watcher`,
`honeypot_listener`, `contain_disrupt_demo`.

**Verified output**: started the collector, then ran `masquerade_detector.py
--self-test`, `honeytoken_watcher.py --self-test`, and `beacon_demo.py` as three
genuinely separate process invocations — no shared state, no shortcuts. Queried
`/events.json` afterward and all three alerts had actually arrived over real HTTP,
each correctly labeled with its source module, technique ID, and severity:

```
3 events
HIGH masquerade_detector T1036.005 PID 17448 named 'svchost.exe' running from '...'
HIGH honeytoken_watcher  DTE0013   PID 19396 (python.exe) accessed the honeytoken...
HIGH beacon_demo         T1071.001 coefficient of variation 0.007 < 0.15 threshold...
```

### Durable, queryable event history — built and verified

The dashboard above answers "what's happening right now." That's genuinely
useful but it's the whole reason a real vantage point needs more than a live
view: a ring buffer that only holds the last 500 events, wiped clean the
moment the collector process exits, can't answer "which technique fires
most on this machine" or "how did this week compare to last." So every
event the collector receives now gets written to a local SQLite database
(`event-bus/events.db`) in addition to the in-memory ring buffer — the ring
buffer stays fast for the live dashboard, the database is what makes the
history actually durable and queryable.

`self_test()` had to change to prove this properly: it now verifies the
persisted row count with an independent SQL query (not just trusting the
in-memory count), and cleans up only the rows it created itself (`WHERE
source='self_test'`) rather than wiping the whole database — a self-test
that nukes real accumulated history on every run would defeat the entire
point of durability.

**Verified output, live, across two genuinely separate collector
processes** (not one process pretending to be two): started the collector,
ran `masquerade_detector.py --self-test` and `exfil_demo.py` against it,
**stopped the collector entirely**, confirmed the 3 events were still on
disk with the collector process gone, **started a brand-new collector
process** against the same database, ran `honeytoken_watcher.py --self-test`
against *that* one, then queried the combined history:

```
=== Event history summary (4 total event(s)) ===

By severity:
  HIGH     4

By source:
  exfil_demo                   2
  honeytoken_watcher           1
  masquerade_detector          1

=== Top technique(s) by event count ===
  T1041          2
  DTE0013        1
  T1036.005      1

=== Events per day, last 1 day(s) ===
  2026-08-30  ████████████████████████████████████████ 4
```

All 4 events from both independent sessions, correctly attributed —
confirming the history survives a full collector restart, not just a
crash within one process's lifetime.

```bash
python event-bus/collector.py                    # start it, then open
                                                    # http://127.0.0.1:8790/dashboard
python event-bus/collector.py --self-test         # starts, emits 2 fake events
                                                    # over real HTTP, verifies both
                                                    # landed, shuts down, cleans up

# in any other terminal, once the collector is running:
python shield-detect/process_monitor.py --self-test
python defense-evasion/masquerade_detector.py --self-test
# ...any wired detector — its alerts appear on the dashboard within ~2s

# query the durable history any time - collector doesn't need to be running:
python event-bus/query_history.py --summary
python event-bus/query_history.py --top-techniques 5
python event-bus/query_history.py --since-days 7
python event-bus/query_history.py --technique T1486
python event-bus/query_history.py --trend 7

python realtime-detection/fs_watcher.py --self-test
python realtime-detection/fs_watcher.py --demo-ransomware
python realtime-detection/fs_watcher.py --try-kernel-trace   # honest elevation check

python scorecard/attack_chain_scorecard.py

python detection-engineering/generate_report.py   # writes security_report.html
```

### Real-time filesystem detection — built and verified (item 2)

<div align="center">
  <img src=".github/assets/terminal-transcript.svg" alt="Animated diagram: a terminal window typing out the actual verified transcript — a self-test measuring 0.4ms notification latency, PASSED, then an attempted kernel process trace failing live with x_access_denied()" width="100%">
</div>

<br>

Before writing this, checked live whether real kernel ETW/process tracing was
even reachable from this session — it isn't, and the honest result is more
interesting than a workaround:

```
>>> wmi.WMI().Win32_ProcessStartTrace.watch_for()
x_access_denied()
```

Confirmed: kernel-level process tracing needs Administrator, no user-mode way
around it. So [`realtime-detection/fs_watcher.py`](realtime-detection/fs_watcher.py)
applies real-time notification where it's actually achievable unprivileged:
`ReadDirectoryChangesW`, the real Windows API for asynchronous directory-change
notifications — the filesystem filter driver pushes the event the instant it
happens, instead of a loop asking "did anything change yet?" every N ms. This
can't see a file being *opened for read* (that still needs the blocked kernel
path — no way around that limitation), but it's a genuine, meaningful upgrade
for write-heavy techniques already in this project: ransomware's mass file
encryption (T1486) and collection staging (T1074.001) both currently detect
via before/after snapshot diffing, which only reports what already happened.
This reports each change as it happens, with a rate-based detector that can
escalate **mid-attack**, before the batch even finishes.

**Found and fixed a real bug** building this: the first version had a
`stop()` method that called `CloseHandle()` from the calling thread to
unblock the watcher thread's pending `ReadDirectoryChangesW()` call — this
reliably **deadlocked the whole process**. Closing a handle out from under a
pending *synchronous* cross-thread I/O call is a documented Windows hazard:
`CloseHandle` blocks until that pending call completes, which here never
happens (no further filesystem changes were coming). Fixed by dropping the
synchronous stop entirely — the watcher thread is a daemon, so it dies for
free the instant the process exits; every caller in this module is a
one-shot script invocation anyway.

**Verified output**:
- `--self-test`: notification latency measured at **0.4ms** — compare to the
  12,710ms full `psutil.process_iter()` scan measured in Phase 4.
- `--demo-ransomware`: simulated a 6-file mass-encryption burst; the
  rate-based detector fired `⚠️ HIGH (mid-attack)` after the **3rd** file
  change, while files 4–6 were still being encrypted — PASSED.
- `--try-kernel-trace`: re-confirmed the elevation block live, with the exact
  command to try from an admin terminal printed for the user.

### Attack-chain scorecard — built and verified (item 3)

<div align="center">
  <img src=".github/assets/beacon-waveform-morph.svg" alt="Animated diagram: an oscilloscope trace morphing from irregular organic-looking traffic into perfectly regular, evenly-spaced beacon spikes, with the coefficient of variation reading crossfading from 0.4 (organic) to 0.007 (beacon detected)" width="100%">
  <br>
  <sub>Chain B's opening move, in one signature: the same beacon detector this chain scorecard reuses — a beacon can't help being regular.</sub>
</div>

<br>

[`scorecard/attack_chain_scorecard.py`](scorecard/attack_chain_scorecard.py)
asks a harder question than the single-technique scorecard: does a
**multi-stage** attack survive end-to-end, or get caught somewhere along the
way? It reuses the same real, individually-verified stage functions
(no reimplementation) and chains them into two realistic narratives, scoring
each two ways — `any_stage_caught` (would a defender be alerted at all?) and
`full_chain_caught` (is there complete visibility across every stage?).

**Chain A: Persistence → Credential Access → Exfiltration.** The third stage
formats the same fake credentials the dummy store holds and sends them
through the real exfiltration/DLP channel — not exfil_demo's own canned
card/SSN payload.

**Chain B: Command & Control → Impact.**

**Verified output, live**:
```
Chain A (Credential Theft -> Exfiltration): any_stage_caught=True, full_chain_caught=False
Chain B (C2-Driven Ransomware): any_stage_caught=True, full_chain_caught=True
```
Chain A surfaced a **genuine, previously-unknown gap**: persistence and
credential access are both caught, but the exfiltration stage slips past the
DLP detector in this exact shape — harvested browser credentials aren't
card- or SSN-shaped, and the DLP's regex patterns only match those two
shapes. This is exactly the kind of thing chain-level scoring exists to
surface: individual-technique coverage (4/4 on the single scorecard) does
not automatically mean full end-to-end visibility.

### Unified HTML report generator — built and verified (item 4)

[`detection-engineering/generate_report.py`](detection-engineering/generate_report.py)
runs one live pass — the attack-simulation scorecard, the attack-chain
scorecard (reusing the same `Result` objects from that one pass, not
re-running everything three times), the current Sigma rule set, and the
ATT&CK Navigator coverage — and renders all of it into one self-contained
dark-themed HTML report: summary stat cards, per-technique and per-chain
tables with CAUGHT/MISSED pills, and the Chain A gap called out explicitly.
Every number in it comes from that one real execution, not a template.

**Verified output**: generated `security_report.html`; grep-verified against
the live run — **8 CAUGHT / 1 MISSED** across the report (matching the
scorecard + chain results exactly), Chain A's gap-note correctly present,
22 techniques and 3 Sigma rules both listed.

### Full integration test — all of Phase 5 running together, live

Started the event bus collector, then ran the realtime demo, both
scorecards, and the report generator **as four separate process
invocations** against it — no shared state, no shortcuts. Queried
`/events.json` afterward:

```
13 total events received over real HTTP

  persistence_demo             3
  credential_access_demo       3
  beacon_demo                  3
  ransomware_sim               3
  fs_watcher                   1

By severity: {'HIGH': 10, 'MEDIUM': 3}
```

The counts check out exactly: each of the four wired Phase 2/4 detectors
fired once per script (scorecard, chain scorecard, report generator = 3
executions each), and `fs_watcher` fired once from the realtime demo — proof
that the event bus, the wired detectors, both scorecards, and the report
generator all genuinely cooperate over real HTTP, not just individually.

## Scapy, actually used — three ways, not just for ARP sweeps

Scapy already backed the ARP sweep in `local_discovery.py`/`lan_attack_surface.py`
and the live capture in `packet_capture.py`, but nothing yet exercised
Scapy's own analysis (`rdpcap()`, `.show()`) or its packet-construction side
(build from layers, modify a field). These three modules close that gap.

| Module | ATT&CK/Shield mapping | What it does |
|---|---|---|
| [`shield-collect/scapy_pcap_analysis.py`](shield-collect/scapy_pcap_analysis.py) | Shield Collect (DTE0002) | Pure-Python pcap analysis via `rdpcap()` — protocol summary, top talkers, cleartext-HTTP/legacy-port suspicious indicators, and a `--show N` layer drill-down — no tshark/Wireshark install required, complementing (not replacing) `pcap_analysis.py`'s deeper tshark-powered version |
| [`adversary-in-the-middle/arp_spoof_demo.py`](adversary-in-the-middle/arp_spoof_demo.py) | ATT&CK Adversary-in-the-Middle (T1557.002) | Reads a real `(IP, MAC)` pair from this machine's actual ARP cache, crafts a spoofed conflicting ARP reply with Scapy — built and analyzed entirely in memory, **never sent** with `sendp()`/`send()` — and a real detector flags the conflicting mapping |
| [`packet-crafting/craft_packets.py`](packet-crafting/craft_packets.py) | Scapy fundamentals (build + modify) | Builds a DNS query and a TCP SYN packet from layers (`IP/UDP/DNS`, `IP/TCP`), then modifies a field on an already-built packet — every check verified against the packet object itself, no network I/O at all |

### Verified output

**Scapy pcap analysis**: ran against the same real capture documented in
Phase 1 (`capture_1787836470.pcap`) — protocol counts came back
**35 TCP / 21 UDP / 3 ARP**, an exact match against the numbers `tshark`
reported for that same file back in Phase 1. `--show 5` correctly
drilled into packet 5's Ethernet/IP/TCP layers.

**ARP spoofing**: read this machine's real gateway entry from `arp -a`
(`192.168.1.1 -> 78:17:35:19:df:40`), fed it to the detector as the
legitimate baseline (no alert — correct, first sighting), then crafted a
spoofed reply claiming the same IP now belongs to `de:ad:be:ef:13:37`.
The detector caught the conflict immediately: `⚠️ HIGH: 192.168.1.1 was
78:17:35:19:df:40, now claimed by de:ad:be:ef:13:37 — conflicting ARP
reply, classic cache-poisoning signature`.

**Packet crafting**: built a DNS query (verified `qname=example.com.`,
targeting UDP/53) and a TCP SYN packet (verified `flags=S`, `dport=80`),
then modified the SYN packet's destination port to 8080 and confirmed the
change on the packet object itself (`dport before: 80, after: 8080`) —
every claim checked with an assertion, not just printed.

**Navigator export**: re-ran with T1557.002 added — now **23 techniques**
mapped, JSON round-trip validated.

```bash
python shield-collect/scapy_pcap_analysis.py                 # most recent capture
python shield-collect/scapy_pcap_analysis.py --show 5 [file]  # layer drill-down

python adversary-in-the-middle/arp_spoof_demo.py --self-test

python packet-crafting/craft_packets.py --self-test
python packet-crafting/craft_packets.py --show-dns
python packet-crafting/craft_packets.py --show-tcp
python packet-crafting/craft_packets.py --modify-port 8080
```

## Depth roadmap, item 1: baseline-and-deviate detection

Every fixed-rule detector in this project (`process_monitor.py`'s LOLBin
list, `lan_attack_surface.py`'s port list) flags KNOWN-bad patterns —
useful, but blind to something that looks completely legitimate on its own
and simply has never run on this machine before. This is the complementary
approach: learn what's actually normal for *this specific machine* across
repeated real observations, persisted durably in SQLite (same discipline
as `event-bus/events.db`), then flag anything that doesn't match.

| Module | Shield mapping | What it does |
|---|---|---|
| [`baseline-detection/baseline_monitor.py`](baseline-detection/baseline_monitor.py) | Shield Detect (DTE0007), same tactic as `process_monitor.py` | `--learn` folds one real snapshot (process identity + listening ports) into an accumulating baseline with an observation count per item. `--check` flags anything with zero prior observations as genuinely new |

**Verified output**: the first self-test run immediately surfaced a real
usability bug, not a hypothetical one — with only 2 `--learn` passes, all
137 real processes and 18 real ports on this machine legitimately hadn't
cleared the trust threshold yet, so `--check` printed 150+ "still
establishing trust" lines that buried the two things that actually
mattered. Fixed by summarizing low-trust items as a single count instead
of one line per item — a real fix to reporting, not to the detection logic,
which was already correct.

After the fix, `--self-test` (learns twice from real ambient state, spawns
a genuinely novel temp-copied executable and a demo listening socket on
port 54329, checks, cleans up):

```
⚠️  MEDIUM: Process never seen before on this machine: totally_normal_tool.exe (C:\...\pycyber_baseline_10tbl4o4\totally_normal_tool.exe)
⚠️  HIGH: New listening port never seen before: 54329
(155 item(s) still establishing trust — fewer than 3 observations, not flagged individually)

Self-test PASSED
```

And a genuinely organic finding, unprompted: running `--learn` then
`--check` back-to-back in separate terminal invocations caught
`tail.exe` (Git's bundled coreutils binary) as **never seen before** —
correct, since that was its actual first-ever invocation on this machine,
surfaced by a real, unplanned command during this verification pass, not
a staged example.

```bash
python baseline-detection/baseline_monitor.py --learn
python baseline-detection/baseline_monitor.py --check
python baseline-detection/baseline_monitor.py --self-test
```

## Depth roadmap, item 2: MITRE ATT&CK CTI validation

Every technique ID in `export_navigator_layer.py`'s `TECHNIQUES` list is a
hand-typed string with a hand-typed comment — accurate when written, but
with nothing checking it against reality as MITRE's own taxonomy evolves.
This module closes that gap: it downloads the official, published
enterprise-attack STIX bundle (the actual source of truth the real ATT&CK
Navigator is built from) and cross-checks every one of this project's
mapped techniques against it.

| Module | What it does |
|---|---|
| [`detection-engineering/attack_cti_lookup.py`](detection-engineering/attack_cti_lookup.py) | `--validate` cross-checks all mapped technique IDs against MITRE's live official data (catches typos, deprecated IDs, name drift). `--lookup ID` pulls one technique's official name, tactic(s), and description |

**Verified output — and a genuine, unplanned finding**: all 23 technique
IDs this project claims are confirmed valid, official MITRE ATT&CK
technique IDs — no typos, nothing deprecated. But the validation also
surfaced something this project's own docstrings have silently drifted on:
MITRE's live taxonomy no longer has a "Defense Evasion" tactic. It's been
split into **Stealth** and **Defense Impairment**:

```
✓ T1027         Obfuscated Files or Information                 [stealth]
✓ T1574.009     Path Interception by Unquoted Path               [stealth, execution]
✓ T1036.005     Match Legitimate Resource Name or Location       [stealth]
```

Several modules in this project (`masquerade_detector.py` among them)
still say "MITRE ATT&CK Defense Evasion tactic" in their own docstrings —
technically referencing a tactic name the official source no longer uses.
The technique IDs themselves are still completely correct; only the
tactic *label* in this project's prose has drifted. This is exactly the
kind of thing a hand-maintained comment can't catch on its own, and
exactly why this tool exists — verified against the live source, not
assumed from what the tactic used to be called.

```bash
python detection-engineering/attack_cti_lookup.py --validate
python detection-engineering/attack_cti_lookup.py --lookup T1486
```

## Depth roadmap, item 3: real labeled training pcaps

Every capture this project analyzed before this point was either a live
5-second demo capture on this machine or a synthetic one — never a real,
complex, professionally-labeled malicious traffic sample. This closes
that gap using [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/),
a site that exists specifically to publish labeled pcaps for practicing
traffic analysis, with an explicit training-exercises section for exactly
this use case.

**Downloading this deserved real caution, not just a checklist item**:
the site's own about page warns that some of its zip archives contain
live malware samples (identifiable by "malware" in the filename), and
that even plain pcaps can trip AV/Defender simply for being unfamiliar
traffic. This was flagged to the user explicitly before downloading
anything, with the filename, source, and size stated up front — not
assumed to be fine just because the source is legitimate.

| Module | What it does |
|---|---|
| [`shield-collect/fetch_training_pcap.py`](shield-collect/fetch_training_pcap.py) | Downloads a labeled training pcap zip and extracts it with the site's real password scheme (`infected_YYYYMMDD`, confirmed from their own about page). Refuses anything with "malware" in the filename — a live sample, not a traffic capture — as an extra guard |

**A real, slightly funny bug caught immediately**: the first run refused
to download *any* URL from the site at all, because the malware check
tested the whole URL string — and the site's own domain is literally
`malware-traffic-analysis.net`, so every single link matched. Fixed by
checking just the filename, not the full URL.

**Then, running this project's own tooling against a real 22,473-packet
labeled capture surfaced two more real, independent bugs**, both only
visible at realistic scale — the small demo captures used everywhere
else in this project were too small to expose either one:

1. **`scapy_pcap_analysis.py`'s suspicious-indicators pass was 22:1 noise.**
   The first run flagged 3,946 individual "traffic to port 80" lines
   against only 176 genuine cleartext HTTP request lines — every packet
   on an already-flagged connection got its own line. Fixed by
   summarizing port-80 traffic as one count instead of one line per
   packet; ports 21/23 (rare enough that every sighting matters) still
   flag individually. After the fix, the real signal is immediately
   visible: repeated `POST`/`GET` requests to obfuscated paths
   (`/irpw/`, `/lqjm/`) carrying a persistent session token — a textbook
   HTTP-based C2 beacon pattern.

2. **`pcap_analysis.py`'s "NIC hardware offload" explanation from Phase 1
   was wrong** — and this pcap is what proved it. That section originally
   attributed frames showing as opaque `eth > data` (empty DNS/HTTP/TLS
   sections) to NIC checksum/segmentation offload during live capture.
   This downloaded pcap, from a completely different machine, showed the
   identical symptom — which live-capture hardware effects cannot
   explain. The actual cause: this machine's Wireshark profile has the
   `ip` and `http` dissectors explicitly disabled in
   `%APPDATA%\Wireshark\disabled_protos`. Fixed by passing
   `--enable-protocol` on every tshark invocation, overriding that
   disabled state for just this process without touching saved Wireshark
   preferences. After the fix, the same capture that showed nothing but
   `eth > data` now shows full dissection — DNS, HTTP, Kerberos, SMB2,
   TLS, LDAP — and the original Phase 1 section was corrected in place
   rather than silently edited, since a wrong explanation is worth
   recording the same way a bug fix is.

```bash
python shield-collect/fetch_training_pcap.py <zip-url> --date YYYY-MM-DD
python shield-collect/scapy_pcap_analysis.py shield-collect/training-pcaps/<file>.pcap
python shield-collect/pcap_analysis.py shield-collect/training-pcaps/<file>.pcap
```

## Depth roadmap, item 4: certificate transparency search

From the same "Open Technical Databases" OSINT material as WHOIS
(`domain_age_checker.py`): every publicly-trusted TLS certificate is now
permanently logged in certificate transparency logs — a browser
requirement, not optional — and [crt.sh](https://crt.sh/) makes those
logs searchably public. That finds every subdomain a domain has ever
gotten a certificate for, a passive technique `dns_recon.py`'s
brute-force enumeration can't match since it only finds subdomains it
happens to guess.

| Module | ATT&CK mapping | What it does |
|---|---|---|
| [`reconnaissance/cert_transparency.py`](reconnaissance/cert_transparency.py) | T1596.003 (Search Open Websites/Domains: Digital Certificates) | Queries crt.sh's public JSON API for a domain, deduplicates every subject-alternative-name across every certificate found into a unique hostname list |

**Honest verification status — this one didn't fully pass, and that's
recorded rather than hidden**: crt.sh is a free, community-run service
and was genuinely down at build time — every endpoint on the site,
including the homepage, returned `502 Bad Gateway`, independent of query
parameters or user-agent, confirmed with multiple retries over several
minutes. What *was* verified live: the failure-handling path (a real
`502` correctly caught and reported without crashing), and the JSON
parsing/deduplication logic against the real crt.sh response shape via a
mocked response matching their actual API structure — 4 mock certificate
entries correctly collapsed to 3 unique hostnames, with an unrelated
domain correctly filtered out. Marked `50` (not `100`) in the Navigator
export for exactly this reason: the logic is verified, a live successful
query against the real service is not yet confirmed. Worth re-running
`cert_transparency.py` once crt.sh recovers.

```bash
python reconnaissance/cert_transparency.py example.com
```

## What's left (genuinely open, not roadmap filler)

- Contain/Disrupt's network half still needs an elevated terminal to verify
  end-to-end — genuinely blocked from this non-interactive session, not skipped;
  run the command in the Phase 4 section above from an admin terminal to close it.
- True kernel-level process/file-open tracing (the ETW piece
  `ReadDirectoryChangesW` genuinely can't reach) needs Administrator too —
  confirmed live, not assumed; `fs_watcher.py --try-kernel-trace` from an
  elevated terminal is the way to see it actually work.
- Chain A's exfiltration-detection gap (harvested credentials don't match the
  DLP's card/SSN patterns) is a real, open finding, not yet fixed — it's
  exactly the kind of thing this project surfaces rather than hides.
- **11 of 33 modules have never been verified in the environment the headline
  numbers come from.** Six are Windows-only, three need outbound network, two
  need a binary (`arp`, `tshark`) that wasn't present. They are counted as
  BLOCKED, not as passing, and `verify_all.py` names each one — but "blocked"
  is still "unverified here", and running the harness on Windows is what
  actually closes it.
- `honeytoken_watcher` passed its own self-test for a long time while being
  fundamentally broken (see the Proof section). That is a standing reason to
  distrust a green self-test that has only ever run in one environment —
  there may be more of these, and the only way to find them is to keep
  running everything somewhere new.
- Everything else on the original ATT&CK/Shield list has at least one working,
  verified module now, and the event bus gives all of Phase 5 one shared,
  live-verified dashboard whose history now genuinely survives a restart
  (SQLite-backed, see above) — that specific gap is closed. Alerts on that
  bus now also have a lifecycle (assign, correlate, close with a
  disposition) and can trigger automated enrichment playbooks — see the
  SOC-stack section at the end of this README, which is also explicit about
  which tools on the standard SOC list genuinely can't be built here. Real gaps that
  remain are depth, not breadth: none of this is a full EDR (no kernel-level
  hooks without elevation, no persistence across reboots *for the detectors
  themselves* — the event history persists, the detectors don't run as
  background services) — that's a deliberate scope boundary of a portfolio
  project, not an oversight.

**Depth roadmap** — baseline-and-deviate detection, MITRE ATT&CK CTI
validation, real training pcap integration, and certificate transparency
search are all done (see above; the last one pending a live re-verify
once crt.sh recovers from its outage). The IOC-enrichment pipeline
chaining `domain_age_checker.py` and `phishing_url_analyzer.py`
automatically against anything `exfil_demo.py`'s DLP catches **is now
done** — it's the `dlp-exfil-enrichment` playbook in
[`soar/playbooks/`](soar/playbooks/); see the SOC-stack section at the end
of this README, including the three real bugs in existing modules that
building it surfaced. Still queued: testing whether unprivileged Windows
Event Log reads (not a new ETW trace — reading what's already logged) can
layer on top of `fs_watcher.py` as another non-polling telemetry source.

## AI/LLM security — this project's methodology, applied to AI systems

A direct answer to "how does this project's approach make AI systems more
robust": the same two patterns used throughout — heuristic red-flag
scanning (`phishing_url_analyzer.py`) and baseline-and-deviate detection
(`baseline_monitor.py`) — transfer essentially unchanged onto AI/LLM
threats. This project maps to MITRE ATLAS (their ATT&CK equivalent for
AI/ML systems) the same way everything else maps to ATT&CK/Shield — and
every technique ID below was cross-checked against ATLAS's own published
data before use, the same discipline `attack_cti_lookup.py` applies to
ATT&CK IDs, not typed from memory and assumed correct.

| Module | ATLAS mapping | What it does |
|---|---|---|
| [`ai-security/prompt_injection_detector.py`](ai-security/prompt_injection_detector.py) | AML.T0051 (LLM Prompt Injection) | Structural red-flag scanning of text before it reaches an LLM — override phrases, persona/jailbreak hijacks, system-prompt exfiltration framing, hidden zero-width Unicode characters, homoglyphs — the exact same shape as `phishing_url_analyzer.py`, applied to prompts instead of URLs |
| [`ai-security/agent_baseline.py`](ai-security/agent_baseline.py) | AML.T0053 (AI Agent Tool Invocation) | The identical bigram-transition baseline-and-deviate methodology as `baseline_monitor.py`, applied to AI agent tool-call sequences instead of OS processes/ports — learns which tool-to-tool transitions are normal, flags a transition that's never happened before |

**Verified output — prompt injection detector**: self-test against 4
samples (benign, direct override, persona hijack, hidden zero-width
Unicode) — all 4 classified correctly. The hidden-Unicode sample is worth
calling out specifically: `"...sentence​​ignore all previous
instructions​."` looks completely benign to a human eye, and the detector
still caught both the embedded override phrase *and* the zero-width
characters hiding it — `U+200B` present, correctly flagged, exactly the
invisible-to-human/visible-to-model gap this check exists for.

**Verified output — agent tool-call baseline**: learned from 6 realistic
sample agent workflows (15 tool-call transitions total). A known-normal
sequence (`read_file → edit_file → run_tests`) stayed clean. A sequence
built to represent exfiltration-via-agent (`read_file → 
read_credentials_file → send_http_request`) was correctly flagged on
**both** transitions — neither `read_file → read_credentials_file` nor
`read_credentials_file → send_http_request` had ever appeared in the
learned baseline.

**Honest scope note — stated plainly, not implied**: this project has no
live AI agent framework integrated to hook into, so `agent_baseline.py`
isn't learning from real production tool-call telemetry the way
`baseline_monitor.py` learns from this machine's actual real processes.
What's verified is the detection *logic* — genuinely correct, checked
above — against realistic, hand-authored sample workflows standing in for
live telemetry. Any real agent framework that logs `(agent_id, tool_name,
timestamp)` per call is a direct integration point for `--learn`; that
integration itself isn't built.

```bash
python ai-security/prompt_injection_detector.py --self-test
python ai-security/prompt_injection_detector.py "some text to check"

python ai-security/agent_baseline.py --self-test
python ai-security/agent_baseline.py --learn
python ai-security/agent_baseline.py --check read_file edit_file run_tests
```

## Wireshark, three ways deeper

Closes the loop on the `disabled_protos` discovery from the pcap depth-roadmap
item, plus two capabilities the Wireshark **GUI** itself never had from this
project before now — everything up to this point only ever drove `tshark`
(the CLI engine) or opened the raw GUI unfiltered.

| Module | What it does |
|---|---|
| [`shield-collect/wireshark_config_audit.py`](shield-collect/wireshark_config_audit.py) | Read-only by default: reports which protocols this machine's saved Wireshark profile has disabled, flagging only the ones this project's analysis actually depends on (`ip`, `http`, `tcp`, `udp`, `dns`, `tls`, `arp`). `--fix` backs up the file first, then removes only those — any other disabled protocol you set on purpose is left untouched |
| `pcap_analysis.py --open-wireshark` (updated) | Now derives a real display filter from what *that specific run* actually found — cleartext HTTP, cleartext auth, FTP/Telnet, ARP conflicts — and launches the GUI pre-filtered to it, instead of opening the raw unfiltered capture. Falls back to unfiltered if nothing was found or the derived filter fails validation |
| [`shield-collect/export_wireshark_colors.py`](shield-collect/export_wireshark_colors.py) | Generates a real Wireshark colorfilters file from this project's own detection logic — the same checks `pcap_analysis.py` runs, as GUI highlighting rules |

### Verified output

**Config audit**: self-test (against a temp file, never the real profile)
correctly identified `{ip, http}` from a mixed set including unrelated
disabled protocols, and `--fix` removed only those two, leaving the
others alone. The read-only audit against this machine's *actual* profile
correctly found the same 2 (of 23 total disabled) protocols documented in
the pcap depth-roadmap section — confirmed, not re-guessed.

**Filtered GUI launch**: ran the real 22,473-packet training capture
through the updated logic — derived filter `(http.request)`, validated
`True` via `tshark -Y` (the same filter engine the GUI itself uses, so a
syntax error here would fail identically there). Regression-checked
against the small demo capture too: correctly derives no filter when
nothing suspicious is found, falling back to the unfiltered open.

**Coloring rules export**: all 5 rules validated against a real capture
before being written — confirmed this validation is a genuine check, not
a no-op, by first proving it correctly *rejects* a deliberately malformed
filter expression. **Found and fixed a real bug getting here**: the first
version tried validating filters by piping empty stdin into `tshark -r -`
to avoid needing a real pcap file — but tshark refuses stdin as a
"special file" before it even reaches the filter compiler, so it failed
*every* filter, valid or not, for the wrong reason entirely. Fixed by
validating against a real capture file instead, the same pattern
`pcap_analysis.py`'s own filter validation already used.

**Honest limitation, stated plainly**: this project has no way to
screenshot a native desktop application window — only a browser pane —
so the actual *rendered* colors and the filtered GUI's visual result
aren't something this session verified by looking at them. What's
provably true: the colorfilters format matches Wireshark's own shipped
default file byte-for-byte in structure, and every filter expression in
both features is confirmed syntactically valid by the real filter engine.
Whether it looks right is for you to open Wireshark and see.

```bash
python shield-collect/wireshark_config_audit.py            # report only
python shield-collect/wireshark_config_audit.py --fix       # actually fixes your profile

python shield-collect/pcap_analysis.py --open-wireshark [file]   # now filtered

python shield-collect/export_wireshark_colors.py
# then in Wireshark: View > Coloring Rules... > Import > pycyber-colorfilters
```

## The SOC stack, honestly scoped — YARA, case management, SOAR

The standard "SOC tool stack" list looks like this: TIP (MISP, OpenCTI,
VirusTotal), DFIR (Autopsy, YARA, Redline, FTK), vulnerability scanners
(Nessus, OpenVAS), SOAR (Cortex XSOAR, Swimlane), case management
(TheHive, ServiceNow SecOps).

**Most of that list cannot honestly be "implemented" here, and this
section starts by saying which.** Seven of those ten are server platforms
or licensed products. There is no MISP instance, no TheHive server, no
XSOAR tenant and no Nessus license behind this repo. Writing API clients
against services that aren't running anywhere would produce exactly what
this project has refused to ship from the first commit: code whose output
was never verified, because it can't be. An unrunnable `misp_client.py`
would cost more credibility than it adds.

So the three things below are split by what's actually true of each:

| Added | What it honestly is |
|---|---|
| [`dfir/yara_scanner.py`](dfir/yara_scanner.py) + [`dfir/rules/`](dfir/rules/) | **A real integration of a real tool.** YARA is the one product on that list that installs with pip and runs entirely locally, so it's genuinely integrated — not simulated. |
| [`case-management/case_manager.py`](case-management/case_manager.py) | **The function TheHive/ServiceNow perform, not an integration with either.** Built on the SQLite store the event bus already writes to. |
| [`soar/playbook_runner.py`](soar/playbook_runner.py) + [`soar/playbooks/`](soar/playbooks/) | **The function XSOAR/Swimlane perform, not an integration with either.** Trigger-matched playbooks over event-bus alerts. |

Deliberately skipped, with reasons: **MISP/OpenCTI** (no instance to
verify against), **Nessus/OpenVAS** (license or a full server stack;
`lateral-movement/lan_attack_surface.py` already covers the honest local
slice), **Autopsy/Redline/FTK** (GUI forensics suites — nothing to
integrate programmatically), **VirusTotal** (buildable and a natural fit
with `cert_transparency.py`'s existing live-lookup pattern, but it needs
an API key, so it could never sit in the same verified-in-session tier as
everything else here — left out rather than shipped at a lower evidence
bar).

### YARA — the file-side counterpart to the Sigma rules

This project already exports real Sigma rules from its process-monitor
heuristics. Sigma covers what shows up in *logs*; YARA covers what shows
up on *disk*. Two of the five rules are deliberately the same heuristic
as their Sigma equivalent expressed against file content, and carry a
`sigma_equivalent:` field in their metadata pointing at it — that's how
the two formats divide the work in a real pipeline.

What makes the rules mean something: **every rule is verified against a
file that should match it *and* a benign control file that should not, in
the same run.** A rule that has only ever been eyeballed is a guess. And
the true-positive samples aren't invented for the test — they're the
artifacts this repo's own demos actually produce, including a real
AES-256 EAX blob built with the identical construction
`impact/ransomware_sim.py` uses.

<div align="center">
  <img src=".github/assets/yara-verification.svg" alt="Animated diagram: five sample files each connecting to the YARA rule that matched it, all marked PASS, then a benign control file below a divider connecting to nothing and also marked PASS, with a summary bar reading 5 true positives matched, 1 benign control stayed clean, 0 false positives" width="100%">
  <br>
  <sub>The control row is the point. Five rules matching their true positive proves the rules fire; the sixth row proves they don't fire on everything.</sub>
</div>

<br>

#### Verified output — YARA

`python dfir/yara_scanner.py --self-test`, yara-python 4.5.4:

```
  [PASS] sample_encoded_ps.txt              -> PyCyber_Encoded_PowerShell_Command
  [PASS] sample_lolbin_cradle.txt           -> PyCyber_LOLBin_Download_Cradle
  [PASS] sample_staged_data.txt             -> PyCyber_Staged_Sensitive_Data
  [PASS] sample_ransom_note.txt             -> PyCyber_Ransom_Note
  [PASS] sample_file.txt.encrypted          -> PyCyber_High_Entropy_Blob
  [PASS] control_benign.txt                 -> no match (control)

  Benign control matched 0 rule(s) (correct)
  Self-test PASSED
```

**A real false-positive problem, found by running it rather than reading
it.** The first version of the scanner skipped `.yar`/`.yml` files on the
theory that detection content self-matches. Pointing `--scan` at this
repo then reported **9 HIGH matches against the project itself** —
because `shield-detect/process_monitor.py`,
`detection-engineering/export_sigma_rules.py` and the scanner's own
sample generator are `.py` files that embed the very strings they detect.
That's not a bug in YARA and it isn't a reason to weaken the rules; it's
the ordinary exclusion problem every real deployment hits when the
scanner walks over its own signatures. Fixed the way real deployments fix
it — an explicit exclusion list — and the count of suppressed files is
**always printed, never silently dropped**, because an exclusion you
can't see is indistinguishable from a rule that failed to fire:

```
  45 file(s) scanned, 0 match(es).
  11 file(s) excluded as detection content (rules and detectors embed the
  strings they detect — --include-detection-content to scan them anyway)
```

`--include-detection-content` turns the exclusion off so you can watch
the self-match happen instead of taking the explanation on trust.

**Stated caveat, not buried:** `PyCyber_High_Entropy_Blob` is
corroboration, never a verdict. Compressed archives, media and installers
are legitimately high-entropy. It's scoped to small files, reported at
MEDIUM, and the scanner prints that caveat inline every time it fires.

### Case management — the lifecycle the event bus never had

<div align="center">
  <img src=".github/assets/case-correlation.svg" alt="Animated diagram: a before-and-after split. On the left, four alerts each wired to their own separate case. On the right, the same four alerts converging on a single case holding all four events, with footer notes on severity escalation, required dispositions and idempotency" width="100%">
  <br>
  <sub>A design gap found by running the SOAR runner and <code>--auto-triage</code> over the same live events — they disagreed about what an incident is.</sub>
</div>

<br>

After Phase 5, every detector could emit an alert, every alert landed in
one dashboard, and the history survived a restart. But **an alert is not
an investigation.** Nothing in `events.db` could be assigned to a person,
grouped with the other alerts from the same incident, marked a false
positive, or closed. A SOC that can only say "here are 400 alerts" has a
firehose, not a process — and the metric that actually matters (how long
to close one, and how many turn out to be nothing) wasn't computable at
all.

Cases live in the **same** database as events, not a second store: a case
you can't join to its causing events in one query is a spreadsheet.
Closing **requires** a disposition — closing without one throws away the
only feedback signal detection engineering gets, so the CLI refuses it as
a hard error rather than defaulting.

`--auto-triage` groups un-cased alerts by `(source, technique)` inside a
time window, and is **idempotent** — an event already linked to a case is
never pulled into a second one, so it's safe to run on a timer.

The collector now also serves a read-only `/cases` view alongside
`/dashboard` (verified live: `GET /cases` → 200, `GET /cases.json` → 200
with a complete schema). The collector never writes cases; `case-management/`
owns that, and the view degrades to "no cases yet" if the tables don't
exist rather than erroring.

#### Verified output — case management

```
  [PASS] auto-triage created 3 cases from 6 seeded events
  [PASS] 5 eligible events linked, LOW one left out
  [PASS] LOW-severity event stayed un-cased
  [PASS] time window split the same technique into separate cases
  [PASS] re-running auto-triage changed nothing (idempotent)
  [PASS] assign -> in progress -> close with disposition persisted
  [PASS] close with an invalid disposition is rejected
```

Against real cases built from a live collector run:

```
By disposition (closed cases only):
  BENIGN_TRUE_POSITIVE      1   mean time to close 22s

  False-positive rate: 0/1 = 0% of closed cases
```

That false-positive rate is the number the detection-engineering half of
this project actually needs and **could not compute at all** before cases
existed.

**A real bug in the self-test itself, found and fixed.** The first
version diffed the case table before and after `--auto-triage`. That
passed on an empty database and broke the moment it ran against one
holding real un-cased alerts: `auto_triage` processes the whole history,
so the diff swept up cases built from *real* events — and the cleanup
then **deleted them, while printing "real history untouched."** A
self-test that can destroy the data it promises not to touch is worse
than no self-test. Now every assertion and the cleanup are scoped to
cases that actually contain a marker event, and the test passes
repeatedly against a database full of real history.

### SOAR — closing a gap this README had listed as open

<div align="center">
  <img src=".github/assets/soar-pipeline.svg" alt="Animated diagram: a four-stage pipeline following one real alert. A HIGH ransomware alert arrives on the bus, trigger matching selects one of three playbooks, two actions run (indicator extraction then a YARA scan returning two rule matches), and a case is opened with zero humans involved" width="100%">
  <br>
  <sub>A <i>behavioural</i> alert automatically triggering a <i>file-level</i> confirmation, with both findings attached to one case — replayed from a real run.</sub>
</div>

<br>

The previous version of this README listed as still-queued: *"an
IOC-enrichment pipeline chaining `domain_age_checker.py` and
`phishing_url_analyzer.py` automatically against anything
`exfil_demo.py`'s DLP catches."* That chain existed only as something a
human could do by hand in three terminals. It's a playbook now.

Playbooks are **YAML, not Python** — a playbook is configuration an
analyst should be able to change without touching code, and keeping them
declarative is what makes trigger matching testable in isolation. A
playbook referencing an action that doesn't exist is refused at load time,
because a silent no-op is the worst failure mode automation can have.

Two properties make it safe to leave running:

- **Idempotent.** Every `(event, playbook)` pair that runs is recorded in
  a `soar_runs` table, so `--watch` polls without redoing work and a crash
  mid-run resumes cleanly.
- **Observe-only.** Actions enrich, correlate and open cases. Nothing
  quarantines a file, kills a process or blocks an address — the same
  no-destructive-action boundary the rest of this project holds to. A real
  SOAR would do containment; this one deliberately doesn't, and that's a
  scope decision, not an unfinished feature.

**Network honesty:** `check_domain_age` does a live WHOIS lookup. Every
other action is fully local. `--offline` skips the network actions and
says so — which is also how `--self-test` runs, so the test asserts *real*
enrichment output (URL analysis is pure string work) instead of asserting
something that only holds when a registry cooperates.

#### Verified output — SOAR, end to end against a live collector

```
  ▸ dlp-exfil-enrichment on event #31 [HIGH] exfil_demo
      extract_indicators   urls: http://127.0.0.1:8766/upload
      extract_indicators   ips: 127.0.0.1
      analyze_urls         -> [HIGH] host is a raw IP address (127.0.0.1), not a domain name
      check_domain_age     skipped: --offline (WHOIS needs outbound network)
      open_case            opened case #16 [HIGH] and linked event #31

  ▸ ransomware-file-response on event #32 [HIGH] ransomware_sim
      extract_indicators   paths: /home/user/vantage-soc-toolkit/dfir/demo-evidence
      yara_scan            READ_ME_NOW.txt -> PyCyber_Ransom_Note
      yara_scan            report.docx.encrypted -> PyCyber_High_Entropy_Blob
      open_case            opened case #17 [HIGH] and linked event #32
```

That second run is the whole point: a *behavioral* alert (mass extension
change) automatically triggering a *file-level* confirmation (YARA), with
both findings attached to one case — no human in the loop.

#### Three real bugs this found in existing modules

Wiring automation to alerts that only humans had ever read surfaced
things nobody would have noticed by reading the code:

1. **The DLP alert named what leaked but not where to.** `exfil_demo.py`
   reported `card-number-shaped pattern in outbound body` with no
   destination, so the enrichment playbook had *nothing to enrich* — the
   queued pipeline above was a no-op for a reason that had nothing to do
   with the pipeline. Fixed: the alert now carries the destination URL,
   and the chain produces a real finding.
2. **The ransomware alert named what happened but not where.**
   `ransomware_sim.py` reported `6 files changed to '.encrypted'` with no
   path, so `ransomware-file-response` had nothing to scan. Fixed: the
   affected path is in the alert, and the YARA scan above is the result.
3. **The path-extraction regex silently ate the first directory.**
   `/home/user/…` extracted as `/user/…`. The leading `\b` held between
   `home` and the *second* slash but not before the first (space-to-slash
   is two non-word characters, which is not a boundary). Caught by running
   the playbook against a real alert, not by reading the pattern. Fixing
   it then exposed a second one: URLs were being chopped into fake paths
   (`http://example.com/a/b` → `/example.com/a/b`), since a URL's own path
   component looks exactly like a filesystem path — so URLs are now
   stripped before path extraction.

#### And one design gap between the two new modules

Running the SOAR runner and `--auto-triage` over the same live events made
them disagree about what an incident *is*: the runner opened one case per
event while auto-triage grouped them. A burst of related alerts — exactly
what a DLP hit or a ransomware run produces — would have given the analyst
the same alert list they had before case management existed, just with
case numbers on it. Both now correlate on the same `(source, technique)`
key before creating anything, so a burst converges on one investigation no
matter which path reaches it first. Verified with a real 4-alert burst:

```
      open_case            opened case #34 [HIGH] and linked event #72
      open_case            correlated event #73 into existing case #34 (same source+technique, still open)
      open_case            correlated event #74 into existing case #34 (same source+technique, still open)
      open_case            correlated event #75 into existing case #34 (same source+technique, still open)
```

Severity escalates but never de-escalates on correlation: a case that held
a HIGH alert doesn't become MEDIUM because a quieter one joined it.

### Closing the gaps — 1 of 4: YARA in live process memory

The caveats section below used to say YARA here was on-disk only. That was
the most closable of the four, because `yara-python` exposes
`rules.match(pid=...)` and the capability is real rather than simulated.

**Why it matters:** an attacker who decodes a payload in memory, or holds
credentials in a process after reading them, leaves *nothing on disk* for a
file scan to find. On-disk-only YARA cannot see fileless activity at all.

```bash
python dfir/yara_scanner.py --scan-pid 4812          # one process
python dfir/yara_scanner.py --scan-processes         # a sweep, newest first
python dfir/yara_scanner.py --scan-processes --name-filter powershell
```

#### A false positive that justified the whole design

Running memory rules the naive way — reusing the existing disk rules —
**failed immediately, against the benign control process.**
`PyCyber_Staged_Sensitive_Data` fired on a process that contained nothing of
the sort.

The reason is structural, not a tuning problem. That rule says *"a
card-shaped digit run AND a keyword like `account` both appear in this
blob."* For a 2 KB file that is a reasonable correlation. Across ~50 MB of a
Python interpreter's address space, **both are near-guaranteed to exist
somewhere**, and the rule is asking almost nothing.

So rules now declare a `scope` in their metadata, and the scanner **enforces
it** rather than trusting the rule author:

| Scope | Applied to | Why |
|---|---|---|
| `file` | files only | "indicators co-occur somewhere in the blob" logic, sound only when the blob is small and bounded |
| `memory` | live process memory only | written for an unbounded blob; tighter conditions |
| `both` | both | must hold under either assumption |

All five original rules are `file` — one of them (`High_Entropy_Blob`) uses
`filesize`, which has no meaning for a process at all. The two new rules in
[`dfir/rules/pycyber_memory.yar`](dfir/rules/pycyber_memory.yar) are
`memory`. The default for an unmarked rule is `file`, deliberately: a rule
written without thinking about memory *is* a file rule, and guessing wrong
in that direction only costs coverage, while guessing wrong the other way
produces the noisy scanner that makes people stop reading memory alerts.

#### Two more bugs found by running it

- **Kernel threads were reported as "access denied."** A sweep as root
  returned 40/40 denied, which reads as a privilege problem the user could
  fix by running elevated — they cannot. Linux kernel threads have no user
  address space, so a memory scan of one can never match. They're now
  identified and skipped with an accurate message.
- **The cap was spent on the least interesting processes.** Sorting targets
  by PID ascending meant `--max-processes` was consumed entirely by `init`
  and kernel threads. Now sorted newest-first — a process that appeared
  recently is where a fresh compromise actually lives.

#### Verified output — memory scanning

```
=== Live process-memory scan ===
  [PASS] pid 487 (credential material held in memory only) -> PyCyber_Mem_Credential_Material
  [PASS] pid 488 (benign control process) -> no match (correct)
  [info] scanning the scanner's own PID matches 2 rule(s) — which is why it is excluded by default, not a bug
```

Same discipline as the file rules: a live process that **should** match, and
one that **should not**, in the same run. Stable across three consecutive runs.

That `[info]` line is the runtime twin of the disk scanner's
detection-content problem — this process necessarily holds every rule string
in its own memory, because it just compiled them. Its PID and its parent's
are excluded by default, visibly, with `--include-self` to watch it happen.

#### An honest false positive from a real sweep

A `--scan-processes` run in this container flagged
`PyCyber_Mem_Encoded_PowerShell` against a tooling process — one that had
been handling *this project's own README text*, which contains the strings
`powershell` and `FromBase64String` as detection content. The rule was
working exactly as written; the hit was still wrong.

That is the disk scanner's self-match problem at one remove — not the
scanner's own PID, but a process that touched the rules' strings — and it is
the concrete reason the scanner prints *"treat a memory hit as a lead to
confirm, not a verdict"* every time it finds something. Memory scanning
trades precision for reach, and the output says so rather than implying a
confidence it hasn't earned.

### Closing the gaps — 2 of 4: containment, and the threat nobody advertises

Everything in this project up to here *observes*.
[`soar/containment.py`](soar/containment.py) is the first component that
**acts**, which is why the safety logic lives in its own module with its own
self-test rather than being folded into the playbook runner.

#### The attack on your own SOAR

A playbook that contains "the process named in the alert" is only as
trustworthy as the alert — and **alert content is attacker-influenceable**. A
filename, a process name, a URL in a request: these originate outside the
host's trust boundary. An attacker who can get a string into an alert can
make an auto-containment system act on a target of their choosing.

That turns your SOAR into a **denial-of-service primitive aimed at your own
estate, triggered on demand.** It is the part that doesn't appear in the
product brochure, and it drove every design decision here:

| Control | Why |
|---|---|
| **Dry run by default** | A plan is always produced and shown; executing it is a separate decision requiring `--arm` |
| **A protected set that cannot be overridden** | PID 1, kernel threads, this process and its ancestors, and names whose death takes the box down. **No flag disables it** — a safety switch grows a user who sets it permanently |
| **Optional allowlist** | Decide in advance what may be contained, not at alert time. The shipped playbook has one |
| **Reversible first** | `SUSPEND`, never `KILL`, as the default. A suspended process keeps its memory, handles and network state for the investigation; a killed one has destroyed the evidence |
| **A journal** | Every action — including refusals and dry runs — recorded in the same SQLite store as events and cases, so `--undo` works and a case carries its own audit trail |
| **Network blocking confined to TEST-NET-3** | RFC 5737 `203.0.113.0/24` only. Firewalling an arbitrary address from an alert is the same DoS primitive, pointed at the network |

#### A design error the self-test caught

The first version of the never-contain list also included
`python`/`python3`/`bash`/`sh`, reasoning that "this project runs on those."
The self-test spawned a Python victim and **the guard refused to contain
it** — three checks failed.

That list was wrong in both directions. **Over-broad:** on a Linux host a
large share of everything is a Python or shell process, so containment
refuses nearly every legitimate target and the feature is useless.
**Under-protective:** an attacker's payload is very often a Python script or
a shell, so the name carries no signal about whether containing it is safe.

Protecting this tool from containing *itself* is a **PID problem, not a name
problem** — and `protected_pids()` plus `ancestors_of_self()` already solved
it precisely. The name list now covers only processes whose death is
catastrophic, and the self-test asserts that distinction directly rather
than trusting it.

#### Verified output — containment, end to end on a live process

```
  [PASS] dry run leaves the process running untouched
  [PASS] armed SUSPEND actually stops the process
  [PASS] --undo resumes the suspended process
  [PASS] refuses to contain its own process
  [PASS] refuses to contain PID 1
  [PASS] never-contain list covers catastrophic processes only
  [PASS] allowlist mode refuses a non-matching target
  [PASS] BLOCK_IP refuses a real address, allows only TEST-NET-3
  [PASS] undo of a KILL says plainly that it cannot be reversed
```

And through the full playbook path against a real process, with the
process state checked at each step rather than assumed:

```
### 1. DRY RUN (default)
      contain_process   DRY RUN: would SUSPEND 754 (certutil) — nothing was done; pass --arm to act
   state after dry run: S          <- still running, correct

### 2. ARMED
  *** ARMED *** containment will EXECUTE for: malicious-process-containment
      contain_process   [#4] SUSPEND 754 (certutil) -> SUSPENDED (reversible — resume with --undo)
   state after arm: T              <- T = stopped

### 3. JOURNAL
     4  ARMED    SUSPEND   754  certutil   SUSPENDED (reversible — resume with --undo)
     3  dry-run  SUSPEND   754  certutil   DRY RUN: would have executed
     2  dry-run  SUSPEND   750  bash       REFUSED: not in the allowlist
     1  dry-run  SUSPEND   735  python3    REFUSED: not in the allowlist

### 4. UNDO
  action #4 reversed: resumed pid 754
   state after undo: S             <- resumed
```

Note rows 1 and 2: **refusals are journalled too.** A containment system
that silently declines is indistinguishable from one that is broken.

```bash
python soar/containment.py --self-test
python soar/containment.py --list              # the journal
python soar/containment.py --undo 4            # reverse one action
python soar/containment.py --undo-all          # reverse everything still in effect

python soar/playbook_runner.py --run-once            # containment is a DRY RUN
python soar/playbook_runner.py --run-once --arm      # containment EXECUTES
```

**What it still doesn't do:** no network isolation of a whole host, no
account disablement, no EDR-style kernel-level blocking. And `KILL` exists
but no playbook ships with it — `SUSPEND` is the default precisely because
termination destroys the evidence you were about to collect.

### Closing the gaps — 3 of 4: SLA clocks and notification routing

A case list with no clock on it **cannot distinguish a queue being worked
from a queue being ignored** — both look like a column of `OPEN`. That is
the gap, and it is why two clocks exist rather than one:

| Clock | Question it answers |
|---|---|
| **acknowledge** | How long before a human *looked* at it. This is the one that measures whether your alerting is survivable — a case nobody acknowledged for six hours was not triaged, whatever the resolution time eventually says |
| **resolve** | How long before it was *closed with a disposition* |

Targets and notification routes live in
[`case-management/sla_policy.yml`](case-management/sla_policy.yml), not in
code, so changing them is not a code change. The shipped numbers are a
starting point, explicitly not a recommendation — real SLA targets come from
what an organisation has committed to and staffed for, and a number copied
out of someone else's README is worth nothing.

A case reads `AT_RISK` once it has burned 75% of its window. **Warning only
at the moment of breach is warning too late to do anything about it.**

#### Notification routing

Routed by severity, because paging someone for a `LOW` is how people learn
to ignore the pager. Three sinks: `event_bus` (always local), `stdout`, and
`webhook`. **No email/SMS/PagerDuty**, because each needs a credential this
project has nowhere safe to put — an unverifiable integration is exactly
what this repo refuses to ship.

`--check-sla` is **idempotent**: the breach kinds already notified are
recorded on the case. An SLA checker that re-pages every five minutes for
the same unchanged breach trains people to mute it, so this is safe to run
on a timer.

#### Verified output — SLA

```
  [PASS] a fresh case is inside its acknowledge window
  [PASS] a case past 75% of its window reads AT_RISK, before it breaches
  [PASS] an unacknowledged case past its window reads BREACHED
  [PASS] acknowledging stops the acknowledge clock (AT_RISK -> MET)
  [PASS] acknowledging twice does not move the first-look timestamp
  [PASS] breach notification fired for the breached case only
  [PASS] webhook sink delivered over real HTTP to a live receiver
  [PASS] re-checking does not re-notify the same breach (safe on a timer)
  [PASS] closing a case counts as acknowledging it (no false breach)
  [PASS] a malformed policy file degrades to defaults with a warning
```

The webhook check stands up an **actual localhost HTTP listener** and
confirms the POST arrives, the same approach `exfil_demo.py` and the event
bus already use. Asserting that a mock got called only proves the mock works.

Two behaviours worth stating because they are easy to get wrong:

- **Closing a case counts as acknowledging it.** Without this, every
  quickly-closed case reports a false acknowledge breach — an artefact of
  the bookkeeping, not a real miss.
- **Acknowledging late does not un-breach a case.** `--ack` on a case that
  already blew its window still reads `BREACHED`, and the mean-time-to-
  acknowledge reflects the late look. A missed SLA that can be erased by
  eventually getting round to it is not a measurement.

#### The migration, tested against real data

SLA tracking needed two new columns on an existing table. The migration is
**additive only** — `ALTER TABLE ADD COLUMN`, never a drop or a rewrite —
and was verified by building a database with the pre-SLA schema, filling it
with rows, and running the new code against it:

```
OLD schema columns: [... 'closed_at', 'notes']
rows before: events=1 cases=1 links=1

NEW schema columns: [... 'closed_at', 'notes', 'acknowledged_at', 'sla_notified']
rows after:  events=1 cases=1 links=1
legacy case intact: ('pre-existing real case', 'must survive the migration')
```

A tool that silently recreates its own tables on upgrade is a data-loss bug
waiting for the first person who upgrades with real cases open.

```bash
python case-management/case_manager.py --sla          # status + mean time to acknowledge
python case-management/case_manager.py --ack 7 arnav  # record the first look
python case-management/case_manager.py --check-sla    # notify breaches (safe on a timer)
python case-management/case_manager.py --check-sla --policy my_policy.yml
```

### Usage — YARA, cases, SOAR

```bash
pip install -r requirements.txt        # now includes yara-python

# --- verify the whole project first ---
python verify_all.py                   # 22 passed / 0 failed / 11 blocked on Linux

# --- YARA ---
python dfir/yara_scanner.py --self-test
python dfir/yara_scanner.py --list-rules
python dfir/yara_scanner.py --scan <file-or-directory>
python dfir/yara_scanner.py --scan . --include-detection-content   # watch it self-match

# live process memory (needs root / elevated + SeDebugPrivilege)
python dfir/yara_scanner.py --scan-pid 4812
python dfir/yara_scanner.py --scan-processes --max-processes 60
python dfir/yara_scanner.py --scan-processes --name-filter powershell

# --- Case management (needs event-bus/events.db) ---
python case-management/case_manager.py --self-test
python case-management/case_manager.py --auto-triage
python case-management/case_manager.py --list
python case-management/case_manager.py --show 1
python case-management/case_manager.py --assign 1 arnav
python case-management/case_manager.py --set-status 1 IN_PROGRESS
python case-management/case_manager.py --close 1 --disposition FALSE_POSITIVE --note "known admin script"
python case-management/case_manager.py --stats
# live view: http://127.0.0.1:8790/cases while the collector is running

# --- SOAR ---
python soar/playbook_runner.py --self-test
python soar/playbook_runner.py --list-playbooks
python soar/playbook_runner.py --run-once            # WHOIS enrichment enabled
python soar/playbook_runner.py --run-once --offline  # local actions only
python soar/playbook_runner.py --watch --interval 10
```

### What these three do *not* do

Stated plainly so the section above isn't read as more than it is:

- **No threat-intel enrichment against a real TIP.** No MISP, no OpenCTI,
  no VirusTotal. Indicators are extracted and structurally analyzed with
  this project's own modules; none of them is checked against a reputation
  feed.
- ~~**No containment.**~~ **Closed** — `contain_process` and `block_ip` are
  real SOAR actions now, dry-run by default and gated behind `--arm`. See below.
- ~~**YARA is on-disk only.**~~ **Closed** — `--scan-pid` and `--scan-processes`
  now scan live process memory via `rules.match(pid=...)`. See below.
- **Case management has no multi-user auth** — a deliberate non-goal, not a
  gap. ~~No SLA timers, no notification routing.~~ **Both closed** — see
  below. Assignees remain free-text labels rather than accounts: building
  auth would mean storing credentials, and a portfolio security repo has
  nowhere safe to put them.
