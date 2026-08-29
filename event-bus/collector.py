#!/usr/bin/env python
"""
Central event bus — Phase 5. A localhost-only HTTP collector that any
detector in this project can POST alerts to (via the shared
event_bus_client.emit() helper at the project root), plus a live
auto-refreshing dashboard rendering all of them in one place.

The gap this closes: 22+ modules across this project can each catch
something real, but every one of them only ever printed to its own
terminal. Nothing pulled them together. This is the actual point of a
SOC — one pane of glass — which this project genuinely didn't have until
now.

Same localhost-only pattern (127.0.0.1, never 0.0.0.0) as
c2/beacon_demo.py and exfiltration/exfil_demo.py — nothing here is
reachable from outside this machine.

Every event is also persisted to a local SQLite database
(event-bus/events.db) — not just held in the in-memory ring buffer the
dashboard polls. That's what actually turns "one live dashboard" into
"one queryable history": the ring buffer answers "what's happening right
now," the database answers "how many HIGH alerts fired this week" or
"which technique trips most often on this machine" — see
query_history.py, which is a separate tool specifically because a
live-alert view and a historical-analysis view are different jobs, not
because it was convenient to split them.

Usage:
    python event-bus/collector.py              # start the collector
    # open http://127.0.0.1:8790/dashboard, then in any other terminal run
    # a detector that's been wired to emit() — its alerts appear within ~2s

    python event-bus/collector.py --self-test   # starts, emits two fake
                                                  # events over real HTTP,
                                                  # verifies both landed in
                                                  # memory AND in the DB,
                                                  # shuts down, removes only
                                                  # its own test rows (real
                                                  # history is never touched)
"""
import json
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.stdout.reconfigure(encoding="utf-8")

HOST = "127.0.0.1"
PORT = 8790
DB_PATH = Path(__file__).resolve().parent / "events.db"
MAX_EVENTS_HELD = 500

events = []  # in-memory ring buffer, oldest first — backs the live dashboard only
events_lock = threading.Lock()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL NOT NULL,
            source TEXT NOT NULL,
            technique_id TEXT,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_technique ON events(technique_id)")
    conn.commit()
    conn.close()


def persist_event(event):
    """A fresh connection per write, not a shared one — ThreadingHTTPServer
    hands each request its own thread, and sqlite3 connections aren't
    safe to share across threads without extra care. The event volume
    here (alerts, not telemetry firehose) makes a per-write connection
    perfectly cheap."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO events (timestamp, source, technique_id, severity, message) VALUES (?,?,?,?,?)",
            (event["timestamp"], event["source"], event["technique_id"], event["severity"], event["message"]),
        )
        conn.commit()
        conn.close()
    except sqlite3.Error as e:
        print(f"  (DB write failed, event still on the live dashboard: {e})")

DASHBOARD_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>ATT&amp;CK/Shield Labs — Live Event Bus</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family: Consolas, monospace; margin:0; padding:24px; }
  h1 { font-size:20px; margin:0 0 4px 0; }
  .sub { color:#8b949e; font-size:13px; margin-bottom:20px; }
  table { width:100%; border-collapse:collapse; }
  th { text-align:left; padding:8px 10px; border-bottom:1px solid #30363d; color:#8b949e; font-size:12px; text-transform:uppercase; }
  td { padding:8px 10px; border-bottom:1px solid #21262d; font-size:13px; vertical-align:top; }
  tr:hover { background:#161b22; }
  .sev { font-weight:700; padding:2px 8px; border-radius:4px; font-size:11px; display:inline-block; }
  .empty { color:#8b949e; padding:24px 10px; text-align:center; }
  #count { color:#58a6ff; }
  a { color:#58a6ff; }
</style></head>
<body>
  <h1>ATT&amp;CK/Shield Labs — Live Event Bus</h1>
  <div class="sub"><span id="count">0</span> event(s) received — polling every 2s — <a href="/events.json">raw JSON</a></div>
  <table>
    <thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Technique</th><th>Message</th></tr></thead>
    <tbody id="rows"><tr><td class="empty" colspan="5">Waiting for events…</td></tr></tbody>
  </table>
<script>
async function refresh() {
  try {
    const res = await fetch('/events.json');
    const data = await res.json();
    document.getElementById('count').textContent = data.length;
    const rows = document.getElementById('rows');
    if (data.length === 0) { rows.innerHTML = '<tr><td class="empty" colspan="5">Waiting for events…</td></tr>'; return; }
    const colors = {HIGH:'#ff5c5c', MEDIUM:'#ffb84d', LOW:'#7fb3ff', INFO:'#9aa0a6'};
    rows.innerHTML = data.slice().reverse().map(e => {
      const t = new Date(e.timestamp * 1000).toLocaleTimeString();
      const c = colors[e.severity] || '#9aa0a6';
      return `<tr><td>${t}</td><td><span class="sev" style="background:${c}22;color:${c};border:1px solid ${c}55">${e.severity}</span></td><td>${e.source}</td><td>${e.technique_id||''}</td><td>${e.message}</td></tr>`;
    }).join('');
  } catch (e) { /* collector may be mid-restart, just retry next tick */ }
}
refresh();
setInterval(refresh, 2000);
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_POST(self):
        if urlparse(self.path).path != "/event":
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, ValueError):
            self.send_response(400)
            self.end_headers()
            return

        event = {
            "timestamp": body.get("timestamp", time.time()),
            "source": str(body.get("source", "unknown"))[:80],
            "technique_id": str(body.get("technique_id", ""))[:20],
            "severity": str(body.get("severity", "INFO")).upper()[:10],
            "message": str(body.get("message", ""))[:400],
        }
        with events_lock:
            events.append(event)
            if len(events) > MAX_EVENTS_HELD:
                del events[0]
        persist_event(event)

        print(f"  [{event['severity']:6}] {event['source']:28} {event['technique_id']:12} {event['message']}")
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/dashboard"):
            body = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/events.json":
            with events_lock:
                body = json.dumps(events).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def run_server():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def self_test():
    print(f"Starting collector on {HOST}:{PORT} for self-test...")
    server = run_server()
    time.sleep(0.3)

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from event_bus_client import emit

    ok1 = emit(source="self_test", technique_id="T0000", severity="HIGH", message="fake HIGH event")
    ok2 = emit(source="self_test", technique_id="T0000", severity="LOW", message="fake LOW event")
    time.sleep(0.3)

    with events_lock:
        mem_count = len(events)

    # Verify persistence separately from the in-memory count — this is the
    # actual point of the DB layer, so the self-test has to prove it
    # independently, not just trust that memory and disk agree.
    conn = sqlite3.connect(DB_PATH)
    db_count = conn.execute("SELECT COUNT(*) FROM events WHERE source='self_test'").fetchone()[0]
    # Clean up ONLY this self-test's own rows — never truncate real history
    # that happened to already be in the DB from a prior real session.
    conn.execute("DELETE FROM events WHERE source='self_test'")
    conn.commit()
    conn.close()

    server.shutdown()

    passed = ok1 and ok2 and mem_count == 2 and db_count == 2
    print(f"\n{'Self-test PASSED' if passed else 'Self-test FAILED'} — "
          f"{mem_count} event(s) in memory, {db_count} persisted to SQLite and verified by "
          f"query (not just assumed), test rows removed — any real history in {DB_PATH.name} is untouched.")


def main():
    if "--self-test" in sys.argv:
        self_test()
        return
    print(f"Event bus collector listening on http://{HOST}:{PORT}")
    print(f"Dashboard: http://{HOST}:{PORT}/dashboard")
    print(f"History: {DB_PATH} — query it with event-bus/query_history.py")
    print("Waiting for events from any wired detector (Ctrl+C to stop)...\n")
    server = run_server()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
