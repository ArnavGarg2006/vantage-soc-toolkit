#!/usr/bin/env python
"""
Shared client for the Phase 5 event bus (event-bus/collector.py) — imported
by detectors across the project so a single running collector process can
render one live dashboard of everything they catch, instead of each
detector's alerts living only in its own terminal window.

Lives at the project root (not inside event-bus/) specifically so it can be
imported normally — "event-bus" itself is a hyphenated directory name and
can't be `import`ed as a package (the same constraint the scorecard already
worked around with importlib.util for the Phase 2 modules).

Fails silently and fast if the collector isn't running (0.4s timeout,
swallowed exception) — this is strictly additive telemetry. Every module
that calls emit() must keep working identically whether or not a collector
is up; nothing here is a dependency of the detection logic itself.
"""
import time

COLLECTOR_URL = "http://127.0.0.1:8790/event"


def emit(source, technique_id, severity, message):
    """Best-effort POST to the local event collector.

    Returns True if the collector accepted it, False otherwise (not
    running, timed out, whatever) — callers should only use the return
    value for self-test verification, never to change detector behavior.
    """
    try:
        import requests
        requests.post(
            COLLECTOR_URL,
            json={
                "source": source,
                "technique_id": technique_id,
                "severity": severity,
                "message": message,
                "timestamp": time.time(),
            },
            timeout=0.4,
        )
        return True
    except Exception:
        return False
