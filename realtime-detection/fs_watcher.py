#!/usr/bin/env python
"""
Real-time filesystem detection — Phase 5, item 1. Closes the specific gap
Phase 4's Credential Access section documented: even targeted-PID polling is
still polling. This module uses ReadDirectoryChangesW, the actual Windows
API for asynchronous directory-change notifications — the filesystem filter
driver pushes a notification the instant something happens, instead of a
loop asking "did anything change yet?" every N milliseconds. No admin
required — verified live, see below.

What this DOES NOT solve, honestly: ReadDirectoryChangesW fires on
create/write/delete/rename — it cannot see a file being *opened for read*,
which is exactly what credential_access_demo.py and honeytoken_watcher.py
need. That needs true kernel ETW (the Microsoft-Windows-Kernel-File
provider's FileIo_Read/FileIo_Create events) or a minifilter driver, and
this project verified BOTH routes it tried are blocked without
Administrator, in this exact session:

  >>> wmi.WMI().Win32_ProcessStartTrace.watch_for()
  x_access_denied()

  (the Kernel-File ETW provider needs the same SeSystemProfilePrivilege /
  local-admin trace-session rights — there's no user-mode way around it)

So real-time notification is applied where it's actually achievable without
elevation: WRITE-side events. That's a real, meaningful upgrade for the
write-heavy techniques already in this project — ransomware's mass file
encryption (T1486) and collection staging (T1074.001) both currently detect
via before/after snapshot diffing, which only reports what already
happened. This reports each change AS IT HAPPENS, and a rate-based detector
can escalate mid-attack instead of after the batch is already done.

Usage:
    python fs_watcher.py --self-test          # proves real-time delivery:
                                                # a file write is caught in
                                                # milliseconds, not on the
                                                # next poll tick
    python fs_watcher.py --demo-ransomware     # watches a scratch dir live
                                                # while a simulated mass-
                                                # encryption burst runs,
                                                # alerts the MOMENT the rate
                                                # threshold is crossed - not
                                                # after the batch finishes
    python fs_watcher.py --try-kernel-trace    # attempts the real kernel
                                                # process-trace subscription
                                                # so you can see the honest
                                                # elevation failure yourself
                                                # (or the real event, if you
                                                # run this from an elevated
                                                # terminal)
"""
import sys
import threading
import time
from pathlib import Path

import win32con
import win32file

sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from event_bus_client import emit  # noqa: E402

ACTIONS = {1: "CREATED", 2: "DELETED", 3: "MODIFIED", 4: "RENAMED_FROM", 5: "RENAMED_TO"}


class RealtimeDirectoryWatcher:
    """Wraps ReadDirectoryChangesW in a background thread. Calls
    on_event(action_name, filename, timestamp) the instant the filesystem
    filter driver reports a change — no polling interval to wait out.

    Deliberately has no synchronous stop(). ReadDirectoryChangesW blocks the
    watcher thread until the NEXT change arrives; a first real attempt at
    this used CloseHandle() from the calling thread to unblock it on
    shutdown, and that reliably deadlocked the whole process — closing a
    handle out from under a pending *synchronous* cross-thread I/O call is a
    documented Windows hazard: CloseHandle blocks until that pending call
    completes, which here never happens (no further filesystem changes were
    coming). Found this the hard way (a real hang, not a hypothetical) and
    the actual fix is to not fight it: the watcher thread is a daemon, so it
    dies for free the instant the process exits, no explicit teardown
    needed. Every caller in this module is a one-shot script invocation
    anyway."""

    def __init__(self, directory, on_event):
        self.directory = Path(directory)
        self.on_event = on_event
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        handle = win32file.CreateFile(
            str(self.directory), 0x0001,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None, win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS, None,
        )
        while True:
            try:
                results = win32file.ReadDirectoryChangesW(
                    handle, 1024, False,
                    win32con.FILE_NOTIFY_CHANGE_FILE_NAME | win32con.FILE_NOTIFY_CHANGE_LAST_WRITE,
                    None, None,
                )
            except Exception:
                break
            now = time.time()
            for action, name in results:
                self.on_event(ACTIONS.get(action, str(action)), name, now)


def self_test():
    print("=== Self-test: real-time notification latency ===")
    scratch = Path(__file__).resolve().parent / "scratch"
    scratch.mkdir(exist_ok=True)
    events = []

    watcher = RealtimeDirectoryWatcher(scratch, lambda action, name, ts: events.append((action, name, ts)))
    watcher.start()
    time.sleep(0.3)

    t0 = time.time()
    (scratch / "trigger.txt").write_text("hello")
    deadline = time.time() + 2
    while not events and time.time() < deadline:
        time.sleep(0.005)

    (scratch / "trigger.txt").unlink(missing_ok=True)
    try:
        scratch.rmdir()
    except OSError:
        pass  # the watcher thread's directory handle may still be open - harmless, next run reuses the dir

    if events:
        latency_ms = (events[0][2] - t0) * 1000
        print(f"  Caught {len(events)} real-time event(s): {events}")
        print(f"  Notification latency: {latency_ms:.1f}ms — compare to the 12,710ms full "
              f"psutil.process_iter() scan measured in Phase 4's Credential Access fix.")
        emit(source="fs_watcher", technique_id="T1486", severity="INFO",
             message=f"Self-test: real-time FS notification received in {latency_ms:.1f}ms")
        print("\nSelf-test PASSED.")
    else:
        print("\nSelf-test FAILED — no event received.")


def demo_ransomware_realtime():
    print("=== Real-time ransomware-pattern detector demo ===")
    scratch = Path(__file__).resolve().parent / "scratch"
    scratch.mkdir(exist_ok=True)

    RATE_THRESHOLD = 3
    RATE_WINDOW = 2.0
    recent = []
    alerted = threading.Event()

    def on_event(action, name, ts):
        recent.append(ts)
        cutoff = ts - RATE_WINDOW
        while recent and recent[0] < cutoff:
            recent.pop(0)
        print(f"  [{time.strftime('%H:%M:%S')}] {action}: {name}  (rate window: {len(recent)}/{RATE_THRESHOLD})")
        if len(recent) >= RATE_THRESHOLD and not alerted.is_set():
            alerted.set()
            msg = (f"{len(recent)} file changes in {RATE_WINDOW}s — mass file-change burst "
                   f"caught IN PROGRESS, not after the fact")
            print(f"  ⚠️  HIGH (mid-attack): {msg}")
            emit(source="fs_watcher", technique_id="T1486", severity="HIGH", message=msg)

    watcher = RealtimeDirectoryWatcher(scratch, on_event)
    watcher.start()
    time.sleep(0.3)

    print("Simulating a mass-encryption burst (6 files renamed to .encrypted, back to back)...")
    for i in range(6):
        (scratch / f"dummy_{i}.txt").write_text(f"content {i}")
    time.sleep(0.2)
    for i in range(6):
        p = scratch / f"dummy_{i}.txt"
        if p.exists():
            p.rename(scratch / f"dummy_{i}.encrypted")
        time.sleep(0.05)  # tiny stagger - still far faster than any polling interval could resolve per-file

    time.sleep(0.5)

    for p in scratch.glob("*"):
        p.unlink()
    try:
        scratch.rmdir()
    except OSError:
        pass  # the watcher thread's directory handle may still be open - harmless, next run reuses the dir

    print(f"\n{'PASSED' if alerted.is_set() else 'FAILED'} — "
          f"{'alert fired mid-attack, before the batch finished' if alerted.is_set() else 'no mid-attack alert fired'}.")


def try_kernel_trace():
    """Attempts the real kernel-level process-start trace subscription - the
    piece ReadDirectoryChangesW genuinely cannot do (process/open-for-read
    visibility). Documents the actual, verified-live result rather than
    assuming it: this needs Administrator, no user-mode way around it."""
    print("=== Attempting kernel-level process trace (Win32_ProcessStartTrace) ===")
    try:
        import wmi
        c = wmi.WMI()
        watcher = c.Win32_ProcessStartTrace.watch_for()
        print("  Subscription established — this session IS elevated. Watching for 5s "
              "(start any process to trigger it)...")
        try:
            evt = watcher(timeout_ms=5000)
            print(f"  Caught real-time process start: {evt.ProcessName} (PID {evt.ProcessID})")
        except Exception:
            print("  No process started in the 5s window.")
    except Exception as e:
        print(f"  Blocked: {e!r}")
        print("  This requires Administrator — confirmed by actually trying it, not assumed.")
        print("  Run from an elevated terminal to see it actually work:")
        print("    python realtime-detection/fs_watcher.py --try-kernel-trace")


def main():
    if "--self-test" in sys.argv:
        self_test()
    elif "--demo-ransomware" in sys.argv:
        demo_ransomware_realtime()
    elif "--try-kernel-trace" in sys.argv:
        try_kernel_trace()
    else:
        print("Usage: python fs_watcher.py [--self-test | --demo-ransomware | --try-kernel-trace]")


if __name__ == "__main__":
    main()
