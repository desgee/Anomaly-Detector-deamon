import asyncio
import logging
import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("baseline")


# ── Snapshot: what the baseline looks like at a given moment ─────────────────

@dataclass
class BaselineSnapshot:
    """The current computed baseline — mean, stddev, and metadata."""
    mean: float           # average requests per second
    stddev: float         # how much it varies
    error_mean: float     # average error (4xx/5xx) rate
    error_stddev: float   # how much error rate varies
    sample_count: int     # how many seconds of data went into this
    computed_at: float    # Unix timestamp when this was computed
    source: str           # "current_hour", "rolling_30min", or "floor"


# ── Pure statistics helpers ───────────────────────────────────────────────────

def _mean_stddev(values: List[float]) -> Tuple[float, float]:
    
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    mean = sum(values) / n
    variance = sum((x - mean) ** 2 for x in values) / n
    return mean, math.sqrt(variance)


# ── Per-hour accumulator ──────────────────────────────────────────────────────

class HourSlot:
    

    def __init__(self):
        # Each entry: (request_count, error_count) for one second
        self.counts: deque = deque()

    def add(self, req_count: float, err_count: float):
        self.counts.append((req_count, err_count))

    def stats(self) -> Tuple[float, float, float, float, int]:
        """Returns (req_mean, req_stddev, err_mean, err_stddev, n)."""
        if not self.counts:
            return 0.0, 0.0, 0.0, 0.0, 0
        reqs = [c[0] for c in self.counts]
        errs = [c[1] for c in self.counts]
        rm, rs = _mean_stddev(reqs)
        em, es = _mean_stddev(errs)
        return rm, rs, em, es, len(self.counts)

    def __len__(self):
        return len(self.counts)


# ── The baseline engine ───────────────────────────────────────────────────────

class BaselineEngine:
    
    def __init__(self, cfg: dict):
        bc = cfg.get("baseline", {})
        self.rolling_window_secs = bc.get("rolling_window_minutes", 30) * 60
        self.recalc_interval     = bc.get("recalc_interval_seconds", 60)
        self.min_samples         = bc.get("min_samples", 30)
        self.prefer_hour_min     = bc.get("prefer_hour_min_samples", 60)
        self.floor_mean          = bc.get("floor_mean", 0.1)
        self.floor_stddev        = bc.get("floor_stddev", 0.05)

        # Rolling 30-minute window of per-second counts
        self._rolling: deque = deque()  # (ts, req_count, err_count)

        # Per-hour slots — keyed by int(ts // 3600)
        self._hourly: Dict[int, HourSlot] = defaultdict(HourSlot)

        # Accumulator for the current second
        self._current_second: int = int(time.time())
        self._current_req: float = 0.0
        self._current_err: float = 0.0

        # The last computed snapshot — starts at floor values
        self._snapshot = BaselineSnapshot(
            mean=self.floor_mean,
            stddev=self.floor_stddev,
            error_mean=0.0,
            error_stddev=self.floor_stddev,
            sample_count=0,
            computed_at=time.time(),
            source="floor",
        )

        # History of snapshots for the dashboard graph
        self.history: deque = deque(maxlen=500)

        self._last_recalc: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def current(self) -> BaselineSnapshot:
        """The most recently computed baseline snapshot."""
        return self._snapshot

    # ── Recording traffic ─────────────────────────────────────────────────────

    async def record(self, timestamp: float, is_error: bool):
        """
        Called for every incoming log entry.
        Accumulates counts into the current second, flushing when the second rolls over.
        """
        second = int(timestamp)
        async with self._lock:
            if second != self._current_second:
                # The second has changed — flush the completed second
                await self._flush(self._current_second, self._current_req, self._current_err)
                self._current_second = second
                self._current_req = 0.0
                self._current_err = 0.0

            self._current_req += 1.0
            if is_error:
                self._current_err += 1.0

    async def _flush(self, second: int, req: float, err: float):
        """
        Commit one second's data to the rolling window and hourly slot.
        Called under lock.
        """
        ts = float(second)

        # Add to rolling window
        self._rolling.append((ts, req, err))

        # Evict entries older than 30 minutes from the left
        cutoff = ts - self.rolling_window_secs
        while self._rolling and self._rolling[0][0] < cutoff:
            self._rolling.popleft()

        # Add to the correct hourly slot
        hour_key = int(second // 3600)
        self._hourly[hour_key].add(req, err)

        # Clean up hourly slots older than 25 hours
        old_keys = [k for k in self._hourly if k < hour_key - 25]
        for k in old_keys:
            del self._hourly[k]

    # ── Recalculation ─────────────────────────────────────────────────────────

    async def maybe_recalculate(self, audit_cb=None) -> Optional[BaselineSnapshot]:
        """
        If enough time has passed, recompute the baseline.
        Called from the main loop every second or so.
        Returns the new snapshot if recalculated, else None.
        """
        now = time.time()
        if now - self._last_recalc < self.recalc_interval:
            return None

        self._last_recalc = now

        async with self._lock:
            snap = self._compute(now)
            self._snapshot = snap
            self.history.append(snap)

        logger.info(
            f"Baseline recalculated — source={snap.source} "
            f"mean={snap.mean:.3f} stddev={snap.stddev:.3f} n={snap.sample_count}"
        )

        if audit_cb:
            await audit_cb(snap)

        return snap

    def _compute(self, now: float) -> BaselineSnapshot:
        
        current_hour_key = int(now // 3600)
        hour_slot = self._hourly.get(current_hour_key)

        # ── Option 1: prefer the current hour if it has enough data ──────────
        if hour_slot and len(hour_slot) >= self.prefer_hour_min:
            rm, rs, em, es, n = hour_slot.stats()
            return BaselineSnapshot(
                mean        = max(rm, self.floor_mean),
                stddev      = max(rs, self.floor_stddev),
                error_mean  = max(em, 0.0),
                error_stddev= max(es, self.floor_stddev),
                sample_count= n,
                computed_at = now,
                source      = "current_hour",
            )

        # ── Option 2: use the rolling 30-minute window ────────────────────────
        if len(self._rolling) >= self.min_samples:
            reqs = [r for _, r, _ in self._rolling]
            errs = [e for _, _, e in self._rolling]
            rm, rs = _mean_stddev(reqs)
            em, es = _mean_stddev(errs)
            return BaselineSnapshot(
                mean        = max(rm, self.floor_mean),
                stddev      = max(rs, self.floor_stddev),
                error_mean  = max(em, 0.0),
                error_stddev= max(es, self.floor_stddev),
                sample_count= len(reqs),
                computed_at = now,
                source      = "rolling_30min",
            )

        # ── Option 3: not enough data yet — use safe floor values ─────────────
        return BaselineSnapshot(
            mean        = self.floor_mean,
            stddev      = self.floor_stddev,
            error_mean  = 0.0,
            error_stddev= self.floor_stddev,
            sample_count= len(self._rolling),
            computed_at = now,
            source      = "floor",
        )

    async def run_loop(self, audit_cb=None):
        """Background task that triggers recalculation on schedule."""
        while True:
            await asyncio.sleep(self.recalc_interval)
            await self.maybe_recalculate(audit_cb=audit_cb)