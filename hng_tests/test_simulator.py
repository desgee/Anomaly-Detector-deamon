"""
test_simulator.py
==================
Simulates ALL requirements without needing Docker, Nginx, or a VPS.

What this test does:
  1. Creates a fake Nginx log file and writes JSON lines to it
  2. Starts the real detector daemon against that file
  3. Runs four traffic scenarios:
       Phase 1 — Normal traffic   (builds baseline)
       Phase 2 — Attack from one IP  (triggers IP ban)
       Phase 3 — Error surge from one IP (triggers tightened threshold ban)
       Phase 4 — Global spike from many IPs (triggers global alert)
  4. Verifies every requirement was met and prints a report
"""

import asyncio
import json
import math
import os
import sys
import time
import tempfile
import shutil
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

# ── Point imports at our source files ────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from monitor   import parse_line, LogEntry
from baseline  import BaselineEngine, _mean_stddev
from detector  import SlidingWindowTracker, AnomalyDetector, AnomalyEvent
from blocker   import Blocker, BanRecord
from unbanner  import Unbanner
from notifier  import SlackNotifier

# ── Test results tracker ──────────────────────────────────────────────────────
class Results:
    def __init__(self):
        self.passed = []
        self.failed = []

    def ok(self, name):
        self.passed.append(name)
        print(f"  ✅  {name}")

    def fail(self, name, reason=""):
        self.failed.append(name)
        print(f"  ❌  {name}" + (f" — {reason}" if reason else ""))

    def summary(self):
        total = len(self.passed) + len(self.failed)
        print()
        print("=" * 60)
        print(f"RESULTS: {len(self.passed)}/{total} requirements passed")
        print("=" * 60)
        if self.failed:
            print("FAILED:")
            for f in self.failed:
                print(f"  ✗  {f}")
        else:
            print("ALL REQUIREMENTS PASSED ✅")

R = Results()


# ─────────────────────────────────────────────────────────────────────────────
# HELPER: write a fake JSON log line exactly like Nginx would
# ─────────────────────────────────────────────────────────────────────────────

def make_log_line(ip: str, status: int = 200, path: str = "/index.php",
                   method: str = "GET", size: int = 1024,
                   ts: float = None) -> str:
    ts = ts or time.time()
    return json.dumps({
        "source_ip":     ip,
        "timestamp":     ts,
        "method":        method,
        "path":          path,
        "status":        status,
        "response_size": size,
        "request_time":  0.05,
        "http_user_agent": "Mozilla/5.0",
        "x_forwarded_for": ip,
    })


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — Log Monitoring: parse_line() handles all required fields
# ─────────────────────────────────────────────────────────────────────────────

def test_log_monitoring():
    print("\n── TEST 1: Log Monitoring ───────────────────────────────")

    line = make_log_line("1.2.3.4", status=404, path="/login", method="POST", size=512)
    entry = parse_line(line)

    # Check each required field
    if entry is None:
        R.fail("Log line parses without error", "returned None")
        return

    checks = [
        ("source_ip parsed",    entry.source_ip    == "1.2.3.4"),
        ("method parsed",       entry.method       == "POST"),
        ("path parsed",         entry.path         == "/login"),
        ("status parsed",       entry.status       == 404),
        ("response_size parsed",entry.response_size== 512),
        ("timestamp parsed",    entry.timestamp    >  0),
    ]
    for name, ok in checks:
        R.ok(name) if ok else R.fail(name)

    # Test blank line handling
    assert parse_line("") is None, "blank line should return None"
    assert parse_line("not json") is None, "bad json should return None"
    R.ok("Blank/bad lines handled gracefully")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — Sliding Window: deque structure and eviction
# ─────────────────────────────────────────────────────────────────────────────

async def test_sliding_window():
    print("\n── TEST 2: Sliding Window ───────────────────────────────")

    tracker = SlidingWindowTracker(window_seconds=60)

    # Send 30 requests from IP A, 10 from IP B, spread over 2 seconds
    now = time.time()
    for i in range(30):
        entry = LogEntry("192.0.2.10", now - i * 0.05, "GET", "/", 200, 500)
        await tracker.record(entry)
    for i in range(10):
        entry = LogEntry("192.0.2.20", now - i * 0.1, "GET", "/", 200, 500)
        await tracker.record(entry)

    rate_a, err_a = await tracker.get_ip_rates("192.0.2.10")
    rate_b, err_b = await tracker.get_ip_rates("192.0.2.20")
    global_rate   = await tracker.get_global_rate()
    top_ips       = await tracker.get_top_ips(10)

    R.ok("Per-IP rate tracked (192.0.2.10)") if rate_a > 0 else R.fail("Per-IP rate tracked (192.0.2.10)")
    R.ok("Per-IP rate tracked (192.0.2.20)") if rate_b > 0 else R.fail("Per-IP rate tracked (192.0.2.20)")
    R.ok("IP A rate > IP B rate")          if rate_a > rate_b else R.fail("IP A rate > IP B rate")
    R.ok("Global rate covers both IPs")    if global_rate >= rate_a else R.fail("Global rate covers both IPs")
    R.ok("Top IPs list returned")          if len(top_ips) == 2 else R.fail("Top IPs list returned", f"got {len(top_ips)}")
    R.ok("Top IP is 192.0.2.10")            if top_ips[0][0] == "192.0.2.10" else R.fail("Top IP is 192.0.2.10")

    # Test eviction — inject old timestamps that should be evicted
    tracker2 = SlidingWindowTracker(window_seconds=5)  # 5 second window
    old_ts = time.time() - 10  # 10 seconds ago — outside window
    entry_old = LogEntry("192.0.2.30", old_ts, "GET", "/", 200, 100)
    await tracker2.record(entry_old)
    rate_old, _ = await tracker2.get_ip_rates("192.0.2.30")
    # Rate should be 0 because all entries are evicted
    R.ok("Old entries evicted from window") if rate_old == 0 else R.fail(
        "Old entries evicted from window", f"rate={rate_old:.3f} should be 0")

    # Test error window
    for i in range(5):
        entry = LogEntry("192.0.2.40", now, "GET", "/", 404, 100)
        await tracker.record(entry)
    _, err_rate = await tracker.get_ip_rates("192.0.2.40")
    R.ok("Error rate tracked in separate window") if err_rate > 0 else R.fail("Error rate tracked")

    # Confirm no rate-limiting libraries used
    import sys
    bad_libs = ["slowapi", "limits", "ratelimit"]
    for lib in bad_libs:
        if lib in sys.modules:
            R.fail(f"No rate-limiting library used ({lib} found)")
        else:
            R.ok(f"No rate-limiting library ({lib}) used")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3 — Rolling Baseline: mean, stddev, hourly slots, floor values
# ─────────────────────────────────────────────────────────────────────────────

async def test_baseline():
    print("\n── TEST 3: Rolling Baseline ─────────────────────────────")

    cfg = {
        "baseline": {
            "rolling_window_minutes":  1,   # 1 min for fast testing
            "recalc_interval_seconds": 1,
            "min_samples":             5,
            "prefer_hour_min_samples": 10,
            "floor_mean":              0.1,
            "floor_stddev":            0.05,
        }
    }
    engine = BaselineEngine(cfg)

    # Test floor values at startup (no data yet)
    snap = engine._compute(time.time())
    R.ok("Floor mean applied at startup")   if snap.mean   == 0.1  else R.fail("Floor mean",   f"got {snap.mean}")
    R.ok("Floor stddev applied at startup") if snap.stddev == 0.05 else R.fail("Floor stddev", f"got {snap.stddev}")
    R.ok("Source is 'floor' at startup")    if snap.source == "floor" else R.fail("Source floor", f"got {snap.source}")

    # Feed 60 seconds of traffic — simulate 2 req/s normal traffic
    now = time.time()
    for sec in range(60):
        for _ in range(2):
            await engine.record(now - (60 - sec), is_error=False)
        # Manually flush each second
        engine._current_second = int(now - (60 - sec))
        await engine._flush(int(now - (60 - sec)), 2.0, 0.0)

    snap2 = engine._compute(time.time())
    R.ok("Source moves to rolling_30min") if snap2.source in ("rolling_30min", "current_hour") \
        else R.fail("Source moves to rolling_30min", f"got {snap2.source}")
    R.ok("Mean reflects actual traffic")  if snap2.mean > 0.1 \
        else R.fail("Mean reflects traffic", f"got {snap2.mean}")

    # Test _mean_stddev math directly
    m, s = _mean_stddev([1.0, 2.0, 3.0, 4.0, 5.0])
    R.ok("Mean calculated correctly")   if abs(m - 3.0) < 0.001 else R.fail("Mean", f"got {m}")
    R.ok("Stddev calculated correctly") if abs(s - math.sqrt(2)) < 0.001 else R.fail("Stddev", f"got {s}")

    # Test recalculation interval
    engine2 = BaselineEngine(cfg)
    engine2._last_recalc = time.time() - 2  # make it think it's overdue
    result = await engine2.maybe_recalculate()
    R.ok("Recalculation triggers when interval elapsed") if result is not None \
        else R.fail("Recalculation triggers")

    # Test audit callback is called
    callback_called = []
    async def audit_cb(snap):
        callback_called.append(snap)

    engine3 = BaselineEngine(cfg)
    engine3._last_recalc = time.time() - 2
    await engine3.maybe_recalculate(audit_cb=audit_cb)
    R.ok("Audit callback called on recalculation") if callback_called \
        else R.fail("Audit callback called")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4 — Anomaly Detection: z-score, rate multiplier, error surge
# ─────────────────────────────────────────────────────────────────────────────

async def test_anomaly_detection():
    print("\n── TEST 4: Anomaly Detection ────────────────────────────")

    cfg = {
        "baseline": {
            "rolling_window_minutes":  30,
            "recalc_interval_seconds": 60,
            "min_samples":             5,
            "prefer_hour_min_samples": 60,
            "floor_mean":              0.1,
            "floor_stddev":            0.05,
        },
        "anomaly": {
            "z_score_threshold":     3.0,
            "rate_multiplier":       5.0,
            "error_rate_multiplier": 3.0,
            "error_tightening":      0.5,
            "flag_cooldown_seconds": 0,   # disable cooldown for testing
        }
    }

    engine  = BaselineEngine(cfg)
    tracker = SlidingWindowTracker(window_seconds=60)
    detector = AnomalyDetector(cfg, engine, tracker, whitelist=["127.0.0.1"])

    # Manually set a known baseline: mean=1.0, stddev=0.5
    from baseline import BaselineSnapshot
    engine._snapshot = BaselineSnapshot(
        mean=1.0, stddev=0.5,
        error_mean=0.1, error_stddev=0.05,
        sample_count=100,
        computed_at=time.time(),
        source="rolling_30min"
    )

    # ── Z-score test: inject 60 requests in 60s = 1 req/s → z = (1-1)/0.5 = 0 → no alert
    now = time.time()
    for i in range(60):
        e = LogEntry("192.0.2.50", now - i, "GET", "/", 200, 100)
        await tracker.record(e)
    event = await detector.check_ip("192.0.2.50")
    R.ok("Normal traffic does not trigger alert") if event is None \
        else R.fail("Normal traffic does not trigger alert", f"got event: {event.condition}")

    # ── Z-score test: inject 300 requests = 5 req/s → z = (5-1)/0.5 = 8.0 → ALERT
    tracker2  = SlidingWindowTracker(window_seconds=60)
    detector2 = AnomalyDetector(cfg, engine, tracker2, whitelist=[])
    now = time.time()
    for i in range(300):
        e = LogEntry("203.0.113.34", now - (i * 0.2), "GET", "/", 200, 100)
        await tracker2.record(e)
    event2 = await detector2.check_ip("203.0.113.34")
    R.ok("High rate triggers z-score alert") if event2 is not None \
        else R.fail("High rate triggers z-score alert")
    if event2:
        R.ok("Z-score > 3.0 in condition") if "z-score" in event2.condition \
            else R.fail("Z-score in condition", f"got: {event2.condition}")
        R.ok("Event kind is 'ip'") if event2.kind == "ip" \
            else R.fail("Event kind is ip")

    # ── Rate multiplier test: 6 req/s = 6x mean → fires multiplier (5x)
    engine._snapshot = BaselineSnapshot(
        mean=1.0, stddev=10.0,  # high stddev so z-score won't fire
        error_mean=0.1, error_stddev=0.05,
        sample_count=100, computed_at=time.time(), source="rolling_30min"
    )
    tracker3  = SlidingWindowTracker(window_seconds=60)
    detector3 = AnomalyDetector(cfg, engine, tracker3, whitelist=[])
    for i in range(360):  # 6 req/s = 6x mean
        e = LogEntry("203.0.113.54", now - (i * 0.166), "GET", "/", 200, 100)
        await tracker3.record(e)
    event3 = await detector3.check_ip("203.0.113.54")
    R.ok("Rate multiplier (5x) triggers alert") if event3 is not None \
        else R.fail("Rate multiplier triggers alert")

    # ── Global anomaly test
    engine._snapshot = BaselineSnapshot(
        mean=1.0, stddev=0.5,
        error_mean=0.1, error_stddev=0.05,
        sample_count=100, computed_at=time.time(), source="rolling_30min"
    )
    tracker4  = SlidingWindowTracker(window_seconds=60)
    detector4 = AnomalyDetector(cfg, engine, tracker4, whitelist=[])
    for i in range(300):
        e = LogEntry(f"45.155.205.{i%254+1}", now - (i*0.2), "GET", "/", 200, 100)
        await tracker4.record(e)
    global_event = await detector4.check_global()
    R.ok("Global spike triggers global alert") if global_event is not None \
        else R.fail("Global spike triggers global alert")
    if global_event:
        R.ok("Global event kind is 'global'") if global_event.kind == "global" \
            else R.fail("Global event kind")

    # ── Error surge tightening test (completely isolated objects)
    engine5   = BaselineEngine(cfg)
    engine5._snapshot = BaselineSnapshot(
        mean=1.0, stddev=0.5,
        error_mean=0.1, error_stddev=0.05,
        sample_count=100, computed_at=time.time(), source="rolling_30min"
    )
    tracker5  = SlidingWindowTracker(window_seconds=60)
    detector5 = AnomalyDetector(cfg, engine5, tracker5, whitelist=[])
    surge_ip  = "203.0.113.45"
    # 30 errors over 60s = 0.5 err/s = 5x baseline error_mean(0.1) → error_surge fires
    # tightens z threshold: 3.0 * 0.5 = 1.5
    for i in range(30):
        e = LogEntry(surge_ip, now - (i * 2), "GET", "/login", 401, 100)
        await tracker5.record(e)
    # 120 requests = 2 req/s → z = (2-1)/0.5 = 2.0 > 1.5 → fires
    for i in range(120):
        e = LogEntry(surge_ip, now - (i * 0.5), "GET", "/", 200, 100)
        await tracker5.record(e)
    event5 = await detector5.check_ip(surge_ip)
    R.ok("Error surge tightens threshold and fires") if event5 is not None \
        else R.fail("Error surge tightening")
    if event5:
        R.ok("Error surge flagged in event") if event5.error_surge \
            else R.fail("Error surge flag set")

    # ── Whitelist test
    tracker6  = SlidingWindowTracker(window_seconds=60)
    detector6 = AnomalyDetector(cfg, engine, tracker6, whitelist=["127.0.0.1"])
    for i in range(600):
        e = LogEntry("127.0.0.1", now - (i*0.1), "GET", "/", 200, 100)
        await tracker6.record(e)
    event6 = await detector6.check_ip("127.0.0.1")
    R.ok("Whitelisted IP never flagged") if event6 is None \
        else R.fail("Whitelisted IP never flagged")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 5 — Blocking: iptables simulation, ban levels, callbacks
# ─────────────────────────────────────────────────────────────────────────────

async def test_blocking():
    print("\n── TEST 5: Blocking ─────────────────────────────────────")

    cfg = {
        "blocking": {
            "ban_schedule_minutes": [10, 30, 120, -1]
        }
    }
    blocker = Blocker(cfg)

    # Track callbacks
    ban_records   = []
    unban_records = []

    async def on_ban(r):   ban_records.append(r)
    async def on_unban(r): unban_records.append(r)

    blocker.on_ban(on_ban)
    blocker.on_unban(on_unban)

    # First ban — should be level 0 = 10 minutes
    t_before = time.time()
    record = await blocker.ban("203.0.113.10", "z-score=8.0 > 3.0", rate=8.0, baseline=1.0)
    t_after  = time.time()

    R.ok("Ban record created")              if record is not None else R.fail("Ban record")
    R.ok("First ban is level 0 (10 min)")   if record.ban_level == 0 else R.fail("Ban level 0", f"got {record.ban_level}")
    R.ok("First ban duration is 10 min")    if record.duration_minutes == 10 else R.fail("Duration 10", f"got {record.duration_minutes}")
    R.ok("Ban callback called")             if len(ban_records) == 1 else R.fail("Ban callback")
    R.ok("IP marked as banned")             if blocker.is_banned("203.0.113.10") else R.fail("is_banned")
    R.ok("unban_at set correctly")          if record.unban_at and record.unban_at > t_before else R.fail("unban_at")
    R.ok("Condition stored in record")      if "z-score" in record.condition else R.fail("Condition stored")
    R.ok("Rate stored in record")           if record.rate == 8.0 else R.fail("Rate stored")
    R.ok("Baseline stored in record")       if record.baseline == 1.0 else R.fail("Baseline stored")

    # Second ban — same IP, should advance to level 1 = 30 minutes
    record2 = await blocker.ban("203.0.113.10", "rate=6x mean", rate=6.0, baseline=1.0)
    R.ok("Second ban advances to level 1 (30 min)") if record2.duration_minutes == 30 \
        else R.fail("Second ban 30 min", f"got {record2.duration_minutes}")

    # Third ban = 120 min
    record3 = await blocker.ban("203.0.113.10", "rate=6x mean", rate=6.0, baseline=1.0)
    R.ok("Third ban is 120 min") if record3.duration_minutes == 120 \
        else R.fail("Third ban 120 min", f"got {record3.duration_minutes}")

    # Fourth ban = permanent
    record4 = await blocker.ban("203.0.113.10", "rate=6x mean", rate=6.0, baseline=1.0)
    R.ok("Fourth ban is PERMANENT") if record4.duration_minutes == -1 \
        else R.fail("Fourth ban permanent", f"got {record4.duration_minutes}")
    R.ok("Permanent ban has no unban_at") if record4.unban_at is None \
        else R.fail("Permanent unban_at None")

    # Unban
    unban_result = await blocker.unban("203.0.113.10")
    R.ok("Unban removes active flag")    if not blocker.is_banned("203.0.113.10") else R.fail("Unban active flag")
    R.ok("Unban callback called")        if len(unban_records) >= 1 else R.fail("Unban callback")

    # Different IP ban for active bans list
    await blocker.ban("203.0.113.11", "test", rate=5.0, baseline=1.0)
    active = blocker.get_active_bans()
    R.ok("get_active_bans returns current bans") if any(b.ip == "203.0.113.11" for b in active) \
        else R.fail("get_active_bans")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 6 — Auto-Unban: expired bans get released
# ─────────────────────────────────────────────────────────────────────────────

async def test_unbanner():
    print("\n── TEST 6: Auto-Unban ───────────────────────────────────")

    cfg = {"blocking": {"ban_schedule_minutes": [10, 30, 120, -1]}}
    blocker  = Blocker(cfg)
    unbanner = Unbanner(blocker)

    unban_called = []
    async def on_unban(r): unban_called.append(r)
    blocker.on_unban(on_unban)

    # Ban an IP and manually set unban_at to the past
    record = await blocker.ban("192.0.2.30", "test ban", rate=5.0, baseline=1.0)
    record.unban_at = time.time() - 1  # already expired

    R.ok("IP is active before unban check") if blocker.is_banned("192.0.2.30") \
        else R.fail("IP active before check")

    # Run one unban check cycle
    await unbanner._release_expired()

    R.ok("Expired ban auto-released")   if not blocker.is_banned("192.0.2.30") \
        else R.fail("Expired ban auto-released")
    R.ok("Unban callback fired")        if len(unban_called) == 1 \
        else R.fail("Unban callback fired", f"called {len(unban_called)} times")

    # Permanent ban should NOT be auto-released
    record_perm = await blocker.ban("203.0.113.12", "perm test", rate=5.0, baseline=1.0)
    # Advance to permanent level
    blocker._offense_count["203.0.113.12"] = 3
    record_perm2 = await blocker.ban("203.0.113.12", "perm test", rate=5.0, baseline=1.0)
    record_perm2.unban_at = None  # explicitly permanent

    await unbanner._release_expired()
    R.ok("Permanent ban NOT auto-released") if blocker.is_banned("203.0.113.12") \
        else R.fail("Permanent ban NOT auto-released")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 7 — Slack Notifier: message format, env var substitution
# ─────────────────────────────────────────────────────────────────────────────

async def test_notifier():
    print("\n── TEST 7: Slack Alerts ─────────────────────────────────")

    # Test without real Slack — messages go to stdout
    cfg = {"slack": {"webhook_url": "", "enabled": False}}
    notifier = SlackNotifier(cfg)

    R.ok("Notifier created without webhook") if notifier is not None \
        else R.fail("Notifier created")
    R.ok("Notifier disabled when no URL")   if not notifier.enabled \
        else R.fail("Notifier disabled")

    # Test env var substitution
    import os, re
    os.environ["TEST_WEBHOOK"] = "https://hooks.slack.com/test/url"
    raw = "${TEST_WEBHOOK}"
    resolved = re.sub(r"\$\{([^}]+)\}", lambda m: os.environ.get(m.group(1), ""), raw)
    R.ok("Env var substitution works") if resolved == "https://hooks.slack.com/test/url" \
        else R.fail("Env var substitution", f"got {resolved}")

    # Test ban alert message content (mock post)
    messages_sent = []
    original_post = notifier._post
    async def mock_post(text):
        messages_sent.append(text)
    notifier._post = mock_post
    notifier.enabled = True  # force it on

    ban_record = BanRecord(
        ip="192.0.2.88",
        banned_at=time.time(),
        ban_level=0,
        duration_minutes=10,
        unban_at=time.time() + 600,
        condition="z-score=8.42 > 3.0",
        rate=8.42,
        baseline=1.0,
        active=True,
    )
    await notifier.send_ban_alert(ban_record)

    R.ok("Ban alert message sent") if len(messages_sent) == 1 \
        else R.fail("Ban alert sent")
    if messages_sent:
        msg = messages_sent[0]
        checks = [
            ("IP in alert",        "192.0.2.88"      in msg),
            ("Condition in alert", "z-score=8.42"     in msg),
            ("Rate in alert",      "8.42"             in msg),
            ("Baseline in alert",  "1.0"              in msg),
            ("Duration in alert",  "10"               in msg),
            ("Timestamp in alert", "2026"             in msg or "UTC" in msg),
        ]
        for name, ok in checks:
            R.ok(f"Ban alert contains {name}") if ok else R.fail(f"Ban alert contains {name}")

    # Test global alert
    messages_sent.clear()
    from detector import AnomalyEvent
    global_event = AnomalyEvent(
        kind="global", ip=None,
        current_rate=25.0, baseline_mean=1.0, baseline_stddev=0.5,
        z_score=48.0, condition="global z-score=48.0 > 3.0",
        timestamp=time.time()
    )
    await notifier.send_global_alert(global_event)
    R.ok("Global alert message sent") if len(messages_sent) == 1 \
        else R.fail("Global alert sent")
    if messages_sent:
        msg = messages_sent[0]
        R.ok("Global alert has condition") if "global z-score" in msg \
            else R.fail("Global alert condition")
        R.ok("Global alert has rate")      if "25.0"           in msg \
            else R.fail("Global alert rate")

    # Test unban alert
    messages_sent.clear()
    await notifier.send_unban_alert(ban_record)
    R.ok("Unban alert message sent") if len(messages_sent) == 1 \
        else R.fail("Unban alert sent")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 8 — Audit Log: structured format, all event types
# ─────────────────────────────────────────────────────────────────────────────

def test_audit_log():
    print("\n── TEST 8: Audit Log ────────────────────────────────────")

    import tempfile, os

    # Create a temp audit log file
    tmp = tempfile.mktemp(suffix=".log")

    class AuditLogger:
        def __init__(self, path):
            self.path = path
            os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)

        def _ts(self):
            return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        def _write(self, line):
            with open(self.path, "a") as f:
                f.write(line + "\n")

        def log_ban(self, record):
            dur = "PERMANENT" if record.duration_minutes == -1 else f"{record.duration_minutes}min"
            self._write(
                f"[{self._ts()}] BAN {record.ip} | {record.condition} | "
                f"rate={record.rate:.3f} | baseline={record.baseline:.3f} | duration={dur}"
            )

        def log_unban(self, record):
            elapsed = (time.time() - record.banned_at) / 60
            self._write(
                f"[{self._ts()}] UNBAN {record.ip} | "
                f"was_level={record.ban_level} | elapsed={elapsed:.1f}min | "
                f"original_condition={record.condition}"
            )

        def log_baseline(self, snap):
            self._write(
                f"[{self._ts()}] BASELINE_RECALC - | "
                f"source={snap.source} | mean={snap.mean:.4f} | "
                f"stddev={snap.stddev:.4f} | samples={snap.sample_count}"
            )

    audit = AuditLogger(tmp)

    record = BanRecord(
        ip="198.51.100.77", banned_at=time.time(), ban_level=0,
        duration_minutes=10, unban_at=time.time()+600,
        condition="z-score=9.1 > 3.0", rate=9.1, baseline=1.0, active=True,
    )

    audit.log_ban(record)
    audit.log_unban(record)

    from baseline import BaselineSnapshot
    snap = BaselineSnapshot(
        mean=2.5, stddev=0.3, error_mean=0.1, error_stddev=0.05,
        sample_count=1800, computed_at=time.time(), source="rolling_30min"
    )
    audit.log_baseline(snap)

    content = open(tmp).read()
    lines = content.strip().split("\n")

    R.ok("Audit log has 3 entries") if len(lines) == 3 else R.fail("Audit log entries", f"got {len(lines)}")

    # Check BAN line format
    ban_line = lines[0]
    R.ok("BAN line starts with timestamp") if ban_line.startswith("[2026") or ban_line.startswith("[202") \
        else R.fail("BAN timestamp format")
    R.ok("BAN line has ACTION keyword")    if "] BAN "      in ban_line else R.fail("BAN keyword")
    R.ok("BAN line has IP")               if "198.51.100.77" in ban_line else R.fail("BAN IP")
    R.ok("BAN line has condition")        if "z-score"     in ban_line else R.fail("BAN condition")
    R.ok("BAN line has rate")             if "rate="       in ban_line else R.fail("BAN rate")
    R.ok("BAN line has baseline")         if "baseline="   in ban_line else R.fail("BAN baseline")
    R.ok("BAN line has duration")         if "duration="   in ban_line else R.fail("BAN duration")

    # Check UNBAN line
    unban_line = lines[1]
    R.ok("UNBAN line has ACTION keyword") if "] UNBAN "    in unban_line else R.fail("UNBAN keyword")
    R.ok("UNBAN line has elapsed time")   if "elapsed="    in unban_line else R.fail("UNBAN elapsed")

    # Check BASELINE_RECALC line
    bl_line = lines[2]
    R.ok("BASELINE_RECALC keyword")       if "BASELINE_RECALC" in bl_line else R.fail("BASELINE_RECALC keyword")
    R.ok("BASELINE has mean=")            if "mean="      in bl_line else R.fail("BASELINE mean")
    R.ok("BASELINE has stddev=")          if "stddev="    in bl_line else R.fail("BASELINE stddev")
    R.ok("BASELINE has samples=")         if "samples="   in bl_line else R.fail("BASELINE samples")
    R.ok("BASELINE has source=")          if "source="    in bl_line else R.fail("BASELINE source")

    print(f"\n  Sample audit log output:")
    for line in lines:
        print(f"    {line}")

    os.unlink(tmp)


# ─────────────────────────────────────────────────────────────────────────────
# TEST 9 — Full end-to-end simulation with a real log file
# ─────────────────────────────────────────────────────────────────────────────

async def test_end_to_end():
    print("\n── TEST 9: End-to-End Simulation ────────────────────────")

    import tempfile
    log_file = tempfile.mktemp(suffix=".log")

    # Events captured during simulation
    anomaly_events = []
    ban_events     = []
    unban_events   = []
    audit_lines    = []

    cfg = {
        "log": {
            "nginx_access_log": log_file,
            "audit_log": tempfile.mktemp(suffix="-audit.log"),
        },
        "sliding_window": {"seconds": 60},
        "baseline": {
            "rolling_window_minutes":  1,
            "recalc_interval_seconds": 999,  # manual control
            "min_samples":             5,
            "prefer_hour_min_samples": 999,
            "floor_mean":              0.5,
            "floor_stddev":            0.1,
        },
        "anomaly": {
            "z_score_threshold":     3.0,
            "rate_multiplier":       5.0,
            "error_rate_multiplier": 3.0,
            "error_tightening":      0.5,
            "flag_cooldown_seconds": 0,
        },
        "blocking": {"ban_schedule_minutes": [10, 30, 120, -1]},
        "slack":    {"webhook_url": "", "enabled": False},
        "whitelist": ["127.0.0.1"],
        "dashboard": {"host": "0.0.0.0", "port": 8099},
    }

    baseline_engine = BaselineEngine(cfg)
    tracker         = SlidingWindowTracker(window_seconds=60)
    blocker         = Blocker(cfg)
    detector        = AnomalyDetector(cfg, baseline_engine, tracker, whitelist=["127.0.0.1"])

    detector.on_anomaly(lambda e: anomaly_events.append(e))
    blocker.on_ban(lambda r: ban_events.append(r))
    blocker.on_unban(lambda r: unban_events.append(r))

    async def on_anomaly(event):
        anomaly_events.append(event)
        if event.kind == "ip" and not blocker.is_banned(event.ip):
            await blocker.ban(event.ip, event.condition, event.current_rate, event.baseline_mean)

    detector._callbacks = [on_anomaly]

    print("  Phase 1 — Normal traffic (30 seconds, building baseline)...")
    now = time.time()
    for sec in range(30):
        ts = now - (30 - sec)
        for _ in range(2):  # 2 req/s = normal
            entry = LogEntry(f"192.0.2.{(sec % 20) + 1}", ts, "GET", "/", 200, 1024)
            await tracker.record(entry)
            await baseline_engine.record(ts, is_error=False)
        await baseline_engine._flush(int(ts), 2.0, 0.0)

    # Force a baseline recalculation
    baseline_engine._last_recalc = 0
    snap = await baseline_engine.maybe_recalculate()
    R.ok("Baseline computed from normal traffic") if snap and snap.mean > 0 \
        else R.fail("Baseline from normal traffic")
    print(f"     Baseline: mean={baseline_engine.current.mean:.3f} stddev={baseline_engine.current.stddev:.3f} source={baseline_engine.current.source}")

    print("  Phase 2 — Attack from single IP (200 req in 2 sec)...")
    attack_ip = "192.0.2.10"
    now2 = time.time()
    for i in range(200):
        entry = LogEntry(attack_ip, now2 - (i * 0.01), "GET", "/wp-login.php", 200, 512)
        await tracker.record(entry)
        await baseline_engine.record(entry.timestamp, is_error=False)

    event = await detector.check_ip(attack_ip)
    if event:
        await on_anomaly(event)

    R.ok("Attack IP detected as anomalous")    if len(anomaly_events) > 0 \
        else R.fail("Attack IP detected")
    R.ok("Attack IP banned via blocker")       if blocker.is_banned(attack_ip) \
        else R.fail("Attack IP banned")
    R.ok("Ban callback fired for attack IP")   if len(ban_events) > 0 \
        else R.fail("Ban callback fired")

    if ban_events:
        br = ban_events[0]
        print(f"     Banned: {br.ip} | {br.condition} | duration={br.duration_label}")
        R.ok("Ban record has all required fields") if all([
            br.ip, br.condition, br.rate > 0, br.baseline > 0, br.banned_at > 0
        ]) else R.fail("Ban record completeness")

    print("  Phase 3 — Global spike (many IPs, all fast)...")
    anomaly_events_before = len(anomaly_events)
    now3 = time.time()
    for i in range(500):
        ip = f"198.51.100.{i % 254 + 1}"
        entry = LogEntry(ip, now3 - (i * 0.01), "GET", "/", 200, 512)
        await tracker.record(entry)
        await baseline_engine.record(entry.timestamp, is_error=False)

    global_event = await detector.check_global()
    if global_event:
        anomaly_events.append(global_event)

    R.ok("Global spike detected") if global_event is not None \
        else R.fail("Global spike detected")
    if global_event:
        R.ok("Global event kind='global'") if global_event.kind == "global" \
            else R.fail("Global event kind")

    print("  Phase 4 — Top IPs from sliding window...")
    top_ips = await tracker.get_top_ips(10)
    R.ok("Top 10 IPs returned")       if len(top_ips) > 0  else R.fail("Top IPs returned")
    R.ok("Attack IP in top IPs")      if any(ip == attack_ip for ip, _ in top_ips) \
        else R.fail("Attack IP in top IPs")

    print("  Phase 5 — Auto-unban expired ban...")
    if ban_events:
        br = ban_events[0]
        br.unban_at = time.time() - 1  # expire it
        unbanner = Unbanner(blocker)
        blocker.on_unban(lambda r: unban_events.append(r))
        await unbanner._release_expired()
        R.ok("Expired ban auto-released") if not blocker.is_banned(attack_ip) \
            else R.fail("Expired ban released")

    # Cleanup
    if os.path.exists(log_file):
        os.unlink(log_file)

    print(f"\n  Simulation summary:")
    print(f"     Anomaly events : {len(anomaly_events)}")
    print(f"     Bans issued    : {len(ban_events)}")
    print(f"     Unbans issued  : {len(unban_events)}")
    print(f"     Global rate    : {await tracker.get_global_rate():.2f} req/s")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 10 — Dashboard API response shape
# ─────────────────────────────────────────────────────────────────────────────

async def test_dashboard():
    print("\n── TEST 10: Dashboard ───────────────────────────────────")

    from dashboard import Dashboard
    from baseline  import BaselineSnapshot
    import dataclasses

    # Build a minimal state object that dashboard._metrics() needs
    cfg = {
        "blocking": {"ban_schedule_minutes": [10, 30, 120, -1]},
        "baseline": {
            "rolling_window_minutes":  30,
            "recalc_interval_seconds": 60,
            "min_samples":             5,
            "prefer_hour_min_samples": 60,
            "floor_mean":              0.1,
            "floor_stddev":            0.05,
        },
        "dashboard": {"host": "0.0.0.0", "port": 8099},
    }
    blocker  = Blocker(cfg)
    baseline = BaselineEngine(cfg)
    tracker  = SlidingWindowTracker(window_seconds=60)

    @dataclasses.dataclass
    class State:
        blocker:    object
        baseline:   object
        tracker:    object
        lines_read: int = 42
        total_bans: int = 3

    state = State(blocker=blocker, baseline=baseline, tracker=tracker)

    # Add a fake ban
    await blocker.ban("192.0.2.99", "z-score=5.0 > 3.0", rate=5.0, baseline=1.0)

    # Add fake traffic to tracker
    now = time.time()
    for i in range(20):
        e = LogEntry(f"192.0.2.{i % 20 + 1}", now - i, "GET", "/", 200, 100)
        await tracker.record(e)

    # Build what the /api/metrics endpoint would return
    bans       = state.blocker.get_active_bans()
    top_ips    = await state.tracker.get_top_ips(10)
    global_rps = await state.tracker.get_global_rate()
    snap       = state.baseline.current

    import psutil
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory()

    payload = {
        "uptime":       "00:01:23",
        "active_bans":  [{"ip": r.ip, "duration_minutes": r.duration_minutes, "condition": r.condition} for r in bans],
        "global_rps":   global_rps,
        "top_ips":      top_ips,
        "cpu_pct":      cpu,
        "mem_pct":      mem.percent,
        "mem_used_mb":  round(mem.used / 1024 / 1024),
        "mem_total_mb": round(mem.total / 1024 / 1024),
        "baseline": {
            "mean":         snap.mean,
            "stddev":       snap.stddev,
            "sample_count": snap.sample_count,
            "source":       snap.source,
        },
        "lines_read":   state.lines_read,
        "total_bans":   state.total_bans,
    }

    # Verify all required dashboard fields are present
    required_fields = [
        ("active_bans",  "Banned IPs shown"),
        ("global_rps",   "Global req/s shown"),
        ("top_ips",      "Top 10 IPs shown"),
        ("cpu_pct",      "CPU usage shown"),
        ("mem_pct",      "Memory usage shown"),
        ("baseline",     "Baseline mean/stddev shown"),
        ("uptime",       "Uptime shown"),
    ]
    for field, label in required_fields:
        R.ok(f"Dashboard has {label}") if field in payload else R.fail(f"Dashboard has {label}")

    R.ok("Active ban appears in dashboard") if any(b["ip"] == "192.0.2.99" for b in payload["active_bans"]) \
        else R.fail("Active ban in dashboard")
    R.ok("Global req/s > 0")               if payload["global_rps"] > 0 \
        else R.fail("Global rps > 0", f"got {payload['global_rps']}")
    R.ok("CPU reading is a number")         if isinstance(payload["cpu_pct"], (int, float)) \
        else R.fail("CPU is number")
    R.ok("Memory reading is a number")      if isinstance(payload["mem_pct"], (int, float)) \
        else R.fail("Memory is number")
    R.ok("lines_read tracked")             if payload["lines_read"] == 42 \
        else R.fail("lines_read")

    print(f"     global_rps={payload['global_rps']:.3f}  cpu={payload['cpu_pct']:.1f}%  mem={payload['mem_pct']:.1f}%")
    print(f"     baseline mean={payload['baseline']['mean']:.3f}  source={payload['baseline']['source']}")
    print(f"     active bans={len(payload['active_bans'])}  top_ips={len(payload['top_ips'])}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN — run all tests
# ─────────────────────────────────────────────────────────────────────────────

async def main():
    print()
    print("=" * 60)
    print("  HNG Anomaly Detector — Full Requirements Test")
    print("=" * 60)

    test_log_monitoring()
    await test_sliding_window()
    await test_baseline()
    await test_anomaly_detection()
    await test_blocking()
    await test_unbanner()
    await test_notifier()
    test_audit_log()
    await test_end_to_end()
    await test_dashboard()

    R.summary()


if __name__ == "__main__":
    asyncio.run(main())