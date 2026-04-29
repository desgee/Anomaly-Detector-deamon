

import argparse
import asyncio
import logging
import os
import re
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import yaml

from monitor  import LogMonitor
from baseline import BaselineEngine
from detector import AnomalyDetector, AnomalyEvent, SlidingWindowTracker
from blocker  import Blocker, BanRecord
from unbanner import Unbanner
from notifier import SlackNotifier
from dashboard import Dashboard

# ── Logging setup ─────────────────────────────────────────────────────────────
# Log to stdout so Docker captures it with `docker logs`
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)8s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("main")


# ── Shared state (read by the dashboard) ─────────────────────────────────────

@dataclass
class DetectorState:
    #Everything the dashboard needs to read, all in one object."""
    blocker:   Blocker
    baseline:  BaselineEngine
    tracker:   SlidingWindowTracker
    lines_read: int = 0
    total_bans: int = 0


# ── Audit logger ──────────────────────────────────────────────────────────────

class AuditLogger:
    #Logs important events in a structured format.

    def __init__(self, path: str):
        self.path = path
        # Create the directory if it doesn't exist
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def _ts(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _write(self, line: str):
        #Write one line to the audit log file AND to stdout.
        print(f"AUDIT: {line}")
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as e:
            logger.warning(f"Audit log write error: {e}")

    def log_ban(self, record: BanRecord):
        dur = "PERMANENT" if record.duration_minutes == -1 else f"{record.duration_minutes}min"
        self._write(
            f"[{self._ts()}] BAN {record.ip} | {record.condition} | "
            f"rate={record.rate:.3f} | baseline={record.baseline:.3f} | duration={dur}"
        )

    def log_unban(self, record: BanRecord):
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


# ── Config loader ─────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    #Load YAML config and substitute ${ENV_VAR} placeholders."""
    with open(path, "r") as f:
        raw = f.read()
    # Replace ${VAR} with actual environment variables
    raw = re.sub(r"\$\{([^}]+)\}", lambda m: os.environ.get(m.group(1), ""), raw)
    return yaml.safe_load(raw)


# ── Main async entrypoint ─────────────────────────────────────────────────────

async def run(config: dict):
    logger.info("=" * 60)
    logger.info("HNG Anomaly Detection Engine starting up")
    logger.info(f"Nginx log: {config['log']['nginx_access_log']}")
    logger.info(f"Audit log: {config['log']['audit_log']}")
    logger.info("=" * 60)

    # ── Create all the components ─────────────────────────────────────────────

    audit     = AuditLogger(config["log"]["audit_log"])
    baseline  = BaselineEngine(config)
    tracker   = SlidingWindowTracker(
        window_seconds=config.get("sliding_window", {}).get("seconds", 60)
    )
    blocker   = Blocker(config)
    unbanner  = Unbanner(blocker)
    notifier  = SlackNotifier(config)
    state     = DetectorState(blocker=blocker, baseline=baseline, tracker=tracker)
    detector  = AnomalyDetector(
        cfg=config,
        baseline=baseline,
        tracker=tracker,
        whitelist=config.get("whitelist", ["127.0.0.1", "::1"]),
    )
    dashboard = Dashboard(config, state)
    log_queue: asyncio.Queue = asyncio.Queue(maxsize=50000)
    monitor   = LogMonitor(config["log"]["nginx_access_log"], log_queue)

    # ── Wire up callbacks ─────────────────────────────────────────────────────
    # When the detector fires an anomaly → decide what to do

    async def on_anomaly(event: AnomalyEvent):
        if event.kind == "ip":
            # Single IP is misbehaving — block it
            if not blocker.is_banned(event.ip):
                await blocker.ban(
                    ip        = event.ip,
                    condition = event.condition,
                    rate      = event.current_rate,
                    baseline  = event.baseline_mean,
                )
        elif event.kind == "global":
            # Global spike — no single IP to block, just alert
            await notifier.send_global_alert(event)

    async def on_ban(record: BanRecord):
        state.total_bans += 1
        audit.log_ban(record)
        await notifier.send_ban_alert(record)

    async def on_unban(record: BanRecord):
        audit.log_unban(record)
        await notifier.send_unban_alert(record)

    async def on_baseline_recalc(snap):
        audit.log_baseline(snap)

    detector.on_anomaly(on_anomaly)
    blocker.on_ban(on_ban)
    blocker.on_unban(on_unban)

    # ── Wrap the queue.put to count lines read ────────────────────────────────
    original_put = log_queue.put
    async def counting_put(entry):
        state.lines_read += 1
        await original_put(entry)
    log_queue.put = counting_put

    # ── Start the dashboard ───────────────────────────────────────────────────
    await dashboard.start()
    logger.info("Dashboard started")

    # ── Launch all background tasks ───────────────────────────────────────────
    tasks = [
        asyncio.create_task(monitor.start(),                          name="monitor"),
        asyncio.create_task(detector.run_loop(log_queue),             name="detector"),
        asyncio.create_task(unbanner.run(),                           name="unbanner"),
        asyncio.create_task(baseline.run_loop(audit_cb=on_baseline_recalc), name="baseline"),
    ]

    logger.info("All systems running. Watching for anomalies...")

    try:
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        logger.info("Shutdown requested.")
    finally:
        monitor.stop()
        await notifier.close()
        await dashboard.stop()
        logger.info("Detector shut down cleanly.")


def main():
    parser = argparse.ArgumentParser(description="HNG Anomaly Detector")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    args = parser.parse_args()

    config = load_config(args.config)
    try:
        asyncio.run(run(config))
    except KeyboardInterrupt:
        logger.info("Stopped by user.")


if __name__ == "__main__":
    main()