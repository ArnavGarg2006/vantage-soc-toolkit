#!/usr/bin/env python
"""
Command and Control — MITRE ATT&CK C2 tactic (T1071.001 Application Layer
Protocol: Web Protocols) paired with a real Shield Detect-style beacon
detector.

Localhost-only, always. The "server" binds to 127.0.0.1 — not 0.0.0.0, so
it is not reachable from any other machine, ever. The "implant" is just a
Python function in the same process making HTTP requests to that local
server. Nothing here touches the internet or another host.

The detection side is the actual point: real C2 beacons check in at
regular intervals (a scheduled task or sleep loop), which produces a
statistically distinctive timing pattern — human/browser traffic is
irregular, beacon traffic has unusually low variance in the time between
requests. This is the same technique tools like RITA and Zeek's
beacon-detection use, demonstrated here on a beacon we control end-to-end.

Usage:
    python beacon_demo.py
"""
import statistics
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import requests

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

HOST = "127.0.0.1"  # loopback only - never reachable from outside this machine
PORT = 8765
BEACON_COUNT = 8
BEACON_INTERVAL = 1.5  # seconds

server_hits = []


class BeaconHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        server_hits.append(time.time())
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ack")

    def log_message(self, format, *args):
        pass  # quiet - we track hits ourselves


def run_server():
    server = HTTPServer((HOST, PORT), BeaconHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def run_beacon_client():
    """Simulates an implant checking in at a fixed interval — the behavior
    being detected, not the payload (there is no payload; it's an HTTP GET)."""
    print(f"Beaconing to http://{HOST}:{PORT}/checkin every {BEACON_INTERVAL}s x {BEACON_COUNT}...")
    timestamps = []
    for i in range(BEACON_COUNT):
        try:
            requests.get(f"http://{HOST}:{PORT}/checkin", timeout=3)
            timestamps.append(time.time())
            print(f"  Beacon {i + 1}/{BEACON_COUNT} sent")
        except requests.RequestException as e:
            print(f"  Beacon {i + 1} failed: {e}")
        time.sleep(BEACON_INTERVAL)
    return timestamps


def detect_beaconing(timestamps, regularity_threshold=0.15):
    """Classic beacon-detection heuristic: low coefficient of variation
    (stdev / mean) in inter-arrival times means suspiciously regular
    check-ins - the hallmark of a scheduled/sleeping implant rather than
    organic human or application traffic."""
    print("\n=== Beacon detection (timing-regularity analysis) ===")
    if len(timestamps) < 3:
        print("  Not enough data points to analyze.")
        return

    deltas = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]
    mean_delta = statistics.mean(deltas)
    stdev_delta = statistics.stdev(deltas)
    cv = stdev_delta / mean_delta if mean_delta else float("inf")

    print(f"  Inter-arrival times: {[round(d, 2) for d in deltas]}")
    print(f"  Mean interval: {mean_delta:.2f}s, stdev: {stdev_delta:.2f}s, "
          f"coefficient of variation: {cv:.3f}")

    if cv < regularity_threshold:
        msg = f"coefficient of variation {cv:.3f} < {regularity_threshold} threshold — automated C2 beaconing pattern"
        print(f"  ⚠️  HIGH: {msg}")
        emit(source="beacon_demo", technique_id="T1071.001", severity="HIGH", message=msg)
    else:
        print(f"  Timing looks irregular enough to be organic traffic (cv >= {regularity_threshold}).")


def main():
    server = run_server()
    time.sleep(0.5)  # let the server actually start
    timestamps = run_beacon_client()
    detect_beaconing(timestamps)
    print(f"\nServer received {len(server_hits)} request(s) total.")
    server.shutdown()


if __name__ == "__main__":
    main()
