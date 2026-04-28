"""
detector.py — Sliding Window Tracker & Anomaly Detector
=========================================================
This is the "short-term memory" plus the "brain" of the system.

SHORT-TERM MEMORY (SlidingWindowTracker):
  Keeps a deque of timestamps for each IP and one global deque.
  Each deque only holds the last 60 seconds of request timestamps.
  Eviction is done by comparing timestamps to (now - 60).

  Why a deque of timestamps instead of a counter?
    A counter would only tell you "N requests this minute" — not when they
    arrived. With timestamps, you can ask "how many in the LAST 60 seconds
    from right now?" which slides continuously, not resetting each minute.

BRAIN (AnomalyDetector):
  For each IP (and globally), it:
  1. Gets the current rate from the sliding window
  2. Gets mean and stddev from the baseline engine
  3. Computes z-score = (rate - mean) / stddev
  4. Fires if z-score > 3.0 OR rate > 5x mean (whichever comes first)
  5. Checks for error surge — if the IP is hammering 4xx/5xx, tighten threshold
  6. Emits an AnomalyEvent for the main loop to handle
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple

from baseline import BaselineEngine, BaselineSnapshot
from monitor import LogEntry

logger = logging.getLogger("detector")


# ── What gets emitted when something bad is detected ─────────────────────────

@dataclass
class AnomalyEvent:
    kind: str              # "ip" or "global"
    ip: Optional[str]      # which IP (None for global events)
    current_rate: float    # req/s right now
    baseline_mean: float   # what normal looks like
    baseline_stddev: float
    z_score: float         # how many stddevs above normal
    condition: str         # human-readable: what rule fired
    timestamp: float       # when this was detected
    error_surge: bool = False  # was error surge tightening active?


# ── The sliding window tracker ────────────────────────────────────────────────

class SlidingWindowTracker:
    """
    Maintains deque-based sliding windows for per-IP and global request rates.

    Data structure for each IP:
        _ip_reqs[ip]  = deque of timestamps (floats)
        _ip_errs[ip]  = deque of timestamps of ERROR requests only

    Data structure for global traffic:
        _global_reqs  = deque of timestamps

    Eviction rule:
        On every access, we walk the LEFT of the deque and pop entries
        that are older than (now - window_seconds).
        Since timestamps are appended in order, the oldest is always on the left.
        This is O(k) where k = number of expired entries.

    Rate formula:
        rate = len(deque) / window_seconds
        (count of timestamps still in window, divided by window size)
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._ip_reqs:  Dict[str, deque] = defaultdict(deque)  # ip → timestamps
        self._ip_errs:  Dict[str, deque] = defaultdict(deque)  # ip → error timestamps
        self._global_reqs: deque = deque()                     # all timestamps
        self._lock = asyncio.Lock()

    async def record(self, entry: LogEntry):
        """
        Record one request from the log.
        Adds its timestamp to the correct per-IP deque and the global deque.
        """
        ts = entry.timestamp
        ip = entry.source_ip
        is_error = entry.status >= 400

        async with self._lock:
            # Add to per-IP request window
            self._ip_reqs[ip].append(ts)

            # If it was an error, also add to the error window
            if is_error:
                self._ip_errs[ip].append(ts)

            # Add to global window
            self._global_reqs.append(ts)

    def _evict(self, dq: deque, cutoff: float):
        """
        Remove all timestamps from the left of the deque that are older than cutoff.
        Since timestamps are always appended in chronological order,
        the deque is sorted — so we can just pop from the left until
        we hit something recent enough.
        """
        while dq and dq[0] < cutoff:
            dq.popleft()

    async def get_ip_rates(self, ip: str) -> Tuple[float, float]:
        """
        Returns (req_per_second, error_per_second) for the given IP
        over the last window_seconds.
        """
        async with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds

            req_dq = self._ip_reqs.get(ip, deque())
            err_dq = self._ip_errs.get(ip, deque())

            self._evict(req_dq, cutoff)
            self._evict(err_dq, cutoff)

            req_rate = len(req_dq) / self.window_seconds
            err_rate = len(err_dq) / self.window_seconds
            return req_rate, err_rate

    async def get_global_rate(self) -> float:
        """Returns global requests per second over the window."""
        async with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            self._evict(self._global_reqs, cutoff)
            return len(self._global_reqs) / self.window_seconds

    async def get_top_ips(self, n: int = 10) -> List[Tuple[str, float]]:
        """Returns the top N IPs by request rate, as [(ip, rate), ...]."""
        async with self._lock:
            now = time.time()
            cutoff = now - self.window_seconds
            rates = []
            for ip, dq in self._ip_reqs.items():
                self._evict(dq, cutoff)
                rates.append((ip, len(dq) / self.window_seconds))
            rates.sort(key=lambda x: x[1], reverse=True)
            return rates[:n]


# ── The anomaly detector ──────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Consumes log entries from the monitor queue and emits AnomalyEvents.

    For every log entry:
      1. Feed it to the sliding window tracker
      2. Feed it to the baseline engine
      3. Check the IP for anomalies
      4. Periodically check global rate for anomalies

    The actual detection math:
      z_score = (current_rate - baseline_mean) / baseline_stddev

      If z_score > threshold  →  anomaly (statistically unusual)
      If current_rate > 5 * baseline_mean  →  anomaly (simple multiplier check)

      Error surge tightening:
        If IP's error_rate > 3 * baseline_error_mean, the IP is probably
        probing for vulnerabilities. We halve the z_score threshold so
        it gets caught sooner.
    """

    def __init__(self, cfg: dict, baseline: BaselineEngine, tracker: SlidingWindowTracker,
                 whitelist: List[str]):
        ac = cfg.get("anomaly", {})
        self.z_threshold      = ac.get("z_score_threshold", 3.0)
        self.rate_multiplier  = ac.get("rate_multiplier", 5.0)
        self.err_multiplier   = ac.get("error_rate_multiplier", 3.0)
        self.err_tightening   = ac.get("error_tightening", 0.5)
        self.flag_cooldown    = ac.get("flag_cooldown_seconds", 30)

        self.baseline = baseline
        self.tracker  = tracker
        self.whitelist = set(whitelist)

        # Track when each IP was last flagged so we don't spam alerts
        self._last_flagged: Dict[str, float] = {}
        self._global_last_flagged: float = 0.0

        # Callbacks that get called when we detect an anomaly
        self._callbacks: List[Callable] = []

    def on_anomaly(self, callback: Callable):
        """Register a callback to be called with each AnomalyEvent."""
        self._callbacks.append(callback)

    async def _emit(self, event: AnomalyEvent):
        """Call all registered callbacks with the anomaly event."""
        for cb in self._callbacks:
            try:
                await cb(event)
            except Exception as e:
                logger.error(f"Anomaly callback error: {e}")

    # ── Detection logic ───────────────────────────────────────────────────────

    def _compute_z(self, rate: float, mean: float, stddev: float) -> float:
        """
        Compute z-score: how many standard deviations is `rate` above `mean`?
        A z-score of 3.0 means the rate is so high it would only happen
        by chance 0.13% of the time in a normal distribution.
        """
        if stddev <= 0:
            return 0.0
        return (rate - mean) / stddev

    async def check_ip(self, ip: str) -> Optional[AnomalyEvent]:
        """
        Check one IP for anomalous behaviour.
        Returns an AnomalyEvent if anomalous, else None.
        """
        # Never block whitelisted IPs
        if ip in self.whitelist:
            return None

        # Cooldown: don't re-flag the same IP too quickly
        now = time.time()
        if now - self._last_flagged.get(ip, 0) < self.flag_cooldown:
            return None

        # Get current rate from sliding window
        req_rate, err_rate = await self.tracker.get_ip_rates(ip)

        # Get baseline
        snap: BaselineSnapshot = self.baseline.current

        # Check for error surge — if the IP is getting lots of errors,
        # it's probably scanning or brute-forcing, so tighten the threshold
        error_surge = (
            snap.error_mean > 0
            and err_rate > self.err_multiplier * snap.error_mean
        )
        # Tighten z threshold if error surge is active
        effective_z_threshold = (
            self.z_threshold * self.err_tightening
            if error_surge
            else self.z_threshold
        )

        # Compute z-score
        z = self._compute_z(req_rate, snap.mean, snap.stddev)

        # Check both conditions — whichever fires first wins
        z_fired    = z > effective_z_threshold
        mult_fired = snap.mean > 0 and req_rate > self.rate_multiplier * snap.mean

        if not (z_fired or mult_fired):
            return None  # Nothing wrong — return early

        # Build the human-readable condition string
        parts = []
        if z_fired:
            parts.append(f"z-score={z:.2f} > {effective_z_threshold:.1f}")
        if mult_fired:
            parts.append(f"rate={req_rate:.2f} > {self.rate_multiplier}x mean={snap.mean:.2f}")
        if error_surge:
            parts.append(f"error_surge (err_rate={err_rate:.2f})")

        # Record that we flagged this IP to enforce cooldown
        self._last_flagged[ip] = now

        return AnomalyEvent(
            kind           = "ip",
            ip             = ip,
            current_rate   = req_rate,
            baseline_mean  = snap.mean,
            baseline_stddev= snap.stddev,
            z_score        = z,
            condition      = " | ".join(parts),
            timestamp      = now,
            error_surge    = error_surge,
        )

    async def check_global(self) -> Optional[AnomalyEvent]:
        """Check global traffic for a spike that no single IP is causing."""
        now = time.time()
        if now - self._global_last_flagged < self.flag_cooldown:
            return None

        rate = await self.tracker.get_global_rate()
        snap = self.baseline.current

        z = self._compute_z(rate, snap.mean, snap.stddev)
        z_fired    = z > self.z_threshold
        mult_fired = snap.mean > 0 and rate > self.rate_multiplier * snap.mean

        if not (z_fired or mult_fired):
            return None

        parts = []
        if z_fired:
            parts.append(f"global z-score={z:.2f} > {self.z_threshold}")
        if mult_fired:
            parts.append(f"global rate={rate:.2f} > {self.rate_multiplier}x mean={snap.mean:.2f}")

        self._global_last_flagged = now

        return AnomalyEvent(
            kind           = "global",
            ip             = None,
            current_rate   = rate,
            baseline_mean  = snap.mean,
            baseline_stddev= snap.stddev,
            z_score        = z,
            condition      = " | ".join(parts),
            timestamp      = now,
        )

    # ── Main analysis loop ────────────────────────────────────────────────────

    async def run_loop(self, log_queue: asyncio.Queue):
        """
        Main loop:
        - Reads log entries from the queue (put there by the monitor)
        - Feeds them to the tracker and baseline
        - Checks the source IP for anomalies after every entry
        - Checks global traffic every second
        """
        last_global_check = time.time()
        checked_this_second: set = set()  # don't check same IP twice per second

        while True:
            try:
                # Wait up to 0.5s for a new log entry
                entry: LogEntry = await asyncio.wait_for(log_queue.get(), timeout=0.5)

                # Feed the entry to both the sliding window and the baseline
                await self.tracker.record(entry)
                await self.baseline.record(entry.timestamp, is_error=entry.status >= 400)

                # Check the source IP (but only once per second per IP)
                ip = entry.source_ip
                if ip not in checked_this_second:
                    checked_this_second.add(ip)
                    event = await self.check_ip(ip)
                    if event:
                        await self._emit(event)

            except asyncio.TimeoutError:
                pass  # No log entries for 0.5s — that's fine

            # Every second: check global rate and reset the per-IP check set
            now = time.time()
            if now - last_global_check >= 1.0:
                last_global_check = now
                checked_this_second.clear()

                event = await self.check_global()
                if event:
                    await self._emit(event)