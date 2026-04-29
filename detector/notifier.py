import asyncio
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Optional

import aiohttp

from blocker import BanRecord
from detector import AnomalyEvent

logger = logging.getLogger("notifier")

# Pattern to substitute ${VAR_NAME} with environment variable values
_ENV_RE = re.compile(r"\$\{([^}]+)\}")


def _resolve_env(value: str) -> str:
    """Replace ${VAR} with the actual environment variable value."""
    return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)


def _utc_now() -> str:
    """Human-readable UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ts_to_str(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class SlackNotifier:
    

    def __init__(self, cfg: dict):
        sc = cfg.get("slack", {})
        raw_url = sc.get("webhook_url", "")
        self.webhook_url = _resolve_env(raw_url)
        self.enabled = sc.get("enabled", True) and bool(self.webhook_url)

        if not self.enabled:
            logger.warning("Slack webhook not configured — alerts will be printed to stdout only")

        self._session: Optional[aiohttp.ClientSession] = None

    async def _session_(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def _post(self, text: str):
        #Send a message to Slack. Falls back to stdout if not configured."""
        if not self.enabled:
            # Print to stdout so it's visible in Docker logs
            print(f"[SLACK ALERT] {text}")
            return

        try:
            session = await self._session_()
            payload = {"text": text}
            async with session.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    logger.error(f"Slack returned {resp.status}: {body}")
        except Exception as e:
            logger.error(f"Slack post failed: {e}")

    # ── Alert types ───────────────────────────────────────────────────────────

    async def send_ban_alert(self, record: BanRecord):
        #Sent when an IP gets blocked."""
        text = (
            f":rotating_light: *IP BANNED* — `{record.ip}`\n"
            f"• *Condition:* {record.condition}\n"
            f"• *Rate:* `{record.rate:.2f}` req/s  "
            f"• *Baseline:* `{record.baseline:.2f}` req/s\n"
            f"• *Ban Duration:* {record.duration_label} (offense #{record.ban_level + 1})\n"
            f"• *Time:* {_ts_to_str(record.banned_at)}"
        )
        await self._post(text)
        logger.info(f"Slack ban alert sent for {record.ip}")

    async def send_unban_alert(self, record: BanRecord):
        #Sent when a ban expires."""
        elapsed = (time.time() - record.banned_at) / 60
        text = (
            f":unlock: *IP UNBANNED* — `{record.ip}`\n"
            f"• *Was banned for:* {elapsed:.1f} minutes\n"
            f"• *Original condition:* {record.condition}\n"
            f"• *Time:* {_utc_now()}"
        )
        await self._post(text)
        logger.info(f"Slack unban alert sent for {record.ip}")

    async def send_global_alert(self, event: AnomalyEvent):
        #Sent when global traffic spikes (Slack only — no IP to block)."""
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f"• *Condition:* {event.condition}\n"
            f"• *Current rate:* `{event.current_rate:.2f}` req/s\n"
            f"• *Baseline mean:* `{event.baseline_mean:.2f}` req/s  "
            f"• *Stddev:* `{event.baseline_stddev:.2f}`\n"
            f"• *Z-score:* `{event.z_score:.2f}`\n"
            f"• *Time:* {_ts_to_str(event.timestamp)}"
        )
        await self._post(text)
        logger.info("Slack global anomaly alert sent")

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()