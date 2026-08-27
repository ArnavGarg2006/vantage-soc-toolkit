#!/usr/bin/env python
"""
Minimal honeypot listener — MITRE Shield Channel (DTE0004, funnel activity
toward a controlled/observed resource) + Facilitate (DTE0007, make a decoy
resource attractive/reachable) tactics.

A bare TCP listener on an unused local port that never speaks a real
protocol — it just accepts the connection, logs who connected and what (if
anything) they sent, and closes. That's a honeypot's entire job: BE the
observed resource, don't do anything else. Binds to 127.0.0.1 only — this
demo version is only reachable from this machine; a real deployment would
bind more broadly and needs its own hardening, out of scope here.

Usage:
    python honeypot_listener.py --self-test   # starts it, connects to it,
                                               # proves the connection gets
                                               # logged, shuts down
"""
import socket
import sys
import threading
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402 — Phase 5 event bus, optional/best-effort

HOST = "127.0.0.1"
PORT = 2222  # commonly-scanned "looks like SSH" port number, nothing real listening here otherwise

connection_log = []


def run_listener(stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    server.settimeout(0.5)
    print(f"Honeypot listening on {HOST}:{PORT}...")

    while not stop_event.is_set():
        try:
            conn, addr = server.accept()
        except socket.timeout:
            continue
        try:
            conn.settimeout(1)
            data = conn.recv(256)
        except socket.timeout:
            data = b""
        entry = {"source": addr, "time": time.time(), "data": data}
        connection_log.append(entry)
        print(f"  Connection from {addr[0]}:{addr[1]} — {len(data)} byte(s) received: {data[:80]!r}")
        emit(source="honeypot_listener", technique_id="DTE0004", severity="MEDIUM",
             message=f"Connection from {addr[0]}:{addr[1]} — {len(data)} byte(s): {data[:80]!r}")
        conn.close()

    server.close()


def self_test():
    stop_event = threading.Event()
    thread = threading.Thread(target=run_listener, args=(stop_event,), daemon=True)
    thread.start()
    time.sleep(0.5)

    print("\nSelf-test: connecting as a fake 'attacker' probe...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.sendall(b"SSH-2.0-FakeScanner_1.0\r\n")
    s.close()
    time.sleep(0.5)

    stop_event.set()
    thread.join(timeout=2)

    print(f"\n{'Self-test PASSED' if connection_log else 'Self-test FAILED'} — "
          f"{len(connection_log)} connection(s) logged.")


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        self_test()
    else:
        print("Usage: python honeypot_listener.py --self-test")
