#!/usr/bin/env python
"""
Exfiltration — MITRE ATT&CK Exfiltration tactic (T1041 Exfiltration Over
C2 Channel) paired with a real DLP-style content inspector.

Same localhost-only pattern as c2/beacon_demo.py (127.0.0.1, never
0.0.0.0) — a local server receives POSTs from a local client. The client
sends synthetic, obviously-fake data shaped like the things DLP tools
actually look for (credit-card-number-shaped digit sequences, SSN-shaped
digit sequences) — never real numbers, generated with an invalid prefix
that fails the Luhn checksum on purpose so nothing here could ever be
mistaken for or misused as a real card number. The server-side handler is
the detector: it inspects every POST body for those patterns and flags
matches, the same technique real DLP/CASB products use on outbound traffic.

Usage:
    python exfil_demo.py
"""
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

sys.stdout.reconfigure(encoding="utf-8")

HOST = "127.0.0.1"
PORT = 8766

# Deliberately Luhn-invalid (starts with 0000, never a real card range) and
# a clearly-fake SSN pattern - shaped like the real thing for pattern
# matching, structurally guaranteed not to be a real number.
FAKE_SENSITIVE_PAYLOAD = (
    "user_notes=Meeting at 3pm. "
    "backup_card=0000-0000-0000-0000. "
    "ref_id=000-00-0000. "
    "nothing else interesting here."
)

CC_PATTERN = re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b")
SSN_PATTERN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

findings = []


class ExfilHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace")

        cc_matches = CC_PATTERN.findall(body)
        ssn_matches = SSN_PATTERN.findall(body)
        if cc_matches:
            findings.append(("HIGH", f"card-number-shaped pattern in outbound body: {cc_matches}"))
        if ssn_matches:
            findings.append(("HIGH", f"SSN-shaped pattern in outbound body: {ssn_matches}"))
        if length > 500:
            findings.append(("LOW", f"unusually large outbound POST body ({length} bytes)"))

        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass


def run_server():
    server = HTTPServer((HOST, PORT), ExfilHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def exfil_client():
    print(f"Sending synthetic 'exfiltrated' data to http://{HOST}:{PORT}/upload (fake data only)...")
    requests.post(f"http://{HOST}:{PORT}/upload", data=FAKE_SENSITIVE_PAYLOAD, timeout=3)


def main():
    server = run_server()
    time.sleep(0.3)
    exfil_client()
    time.sleep(0.3)
    server.shutdown()

    print(f"\n=== DLP inspection results ({len(findings)} finding(s)) ===")
    for severity, reason in findings:
        print(f"  ⚠️  [{severity}] {reason}")
    if not findings:
        print("  Nothing flagged.")


if __name__ == "__main__":
    main()
