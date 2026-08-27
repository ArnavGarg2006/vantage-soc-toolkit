# Python for Cybersecurity

A portfolio of Python security tooling organized around the **MITRE ATT&CK** (offensive
tactics) and **MITRE Shield** (defensive tactics) frameworks — inspired by the structure
of Howard Poston's [Python for Cybersecurity](https://github.com/hposton/python-for-cybersecurity)
course, not a clone of its code. Every script here is real and independently verified live
(see each module's section below), not a template with placeholder output.

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
knowable by combining capture + process data. It also surfaced a genuine networking fact:
most TCP/UDP frames showed as opaque `eth > data` instead of properly dissected IP, a
known effect of NIC hardware checksum/segmentation offload interfering with what Npcap
actually captures — not a bug in the script, a real caveat of live capture on modern NICs.

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

## What's left (genuinely open, not roadmap filler)

- Contain/Disrupt's network half still needs an elevated terminal to verify
  end-to-end — genuinely blocked from this non-interactive session, not skipped;
  run the command in the Phase 4 section above from an admin terminal to close it.
- Everything else on the original ATT&CK/Shield list has at least one working,
  verified module now. Real gaps that remain are depth, not breadth: none of this
  is a full EDR (no kernel-level hooks, no persistence across reboots for the
  detectors themselves, no central logging/alerting pipeline tying the modules
  together) — that's a deliberate scope boundary of a portfolio project, not an
  oversight.
