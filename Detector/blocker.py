
import asyncio
import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

logger = logging.getLogger("blocker")


# ── Ban record — everything we know about one banned IP ──────────────────────

@dataclass
class BanRecord:
    ip: str
    banned_at: float        # when the ban started (Unix time)
    ban_level: int          # 0=first offence, 1=second, etc.
    duration_minutes: int   # -1 = permanent
    unban_at: Optional[float]  # when to lift the ban (None = permanent)
    condition: str          # what triggered the ban
    rate: float             # req/s when banned
    baseline: float         # mean req/s at the time
    active: bool = True     # is this ban still in force?

    @property
    def duration_label(self) -> str:
        if self.duration_minutes == -1:
            return "PERMANENT"
        return f"{self.duration_minutes} min"


# ── The blocker ───────────────────────────────────────────────────────────────

class Blocker:
    """
    Manages iptables rules and ban records.

    Ban schedule (from config):
      Level 0 → 10 minutes
      Level 1 → 30 minutes
      Level 2 → 2 hours
      Level 3+ → permanent

    The level advances each time an IP is banned again after being unbanned.
    """

    def __init__(self, cfg: dict):
        bc = cfg.get("blocking", {})
        self.schedule: List[int] = bc.get("ban_schedule_minutes", [10, 30, 120, -1])

        # ip → BanRecord (only the most recent ban for each IP)
        self._bans: Dict[str, BanRecord] = {}

        # How many times each IP has been banned before (survives unbans)
        self._offense_count: Dict[str, int] = {}

        self._ban_callbacks:   List[Callable] = []
        self._unban_callbacks: List[Callable] = []

    def on_ban(self, cb: Callable):
        self._ban_callbacks.append(cb)

    def on_unban(self, cb: Callable):
        self._unban_callbacks.append(cb)

    def is_banned(self, ip: str) -> bool:
        record = self._bans.get(ip)
        return record is not None and record.active

    def get_active_bans(self) -> List[BanRecord]:
        return [r for r in self._bans.values() if r.active]

    # ── Banning ───────────────────────────────────────────────────────────────

    async def ban(self, ip: str, condition: str, rate: float, baseline: float) -> BanRecord:
        """
        Ban an IP:
        1. Determine ban level and duration
        2. Apply iptables rule
        3. Store record
        4. Notify callbacks (audit log, Slack, etc.)
        """
        # Look up offense history to pick the right level
        level = self._offense_count.get(ip, 0)
        duration = self.schedule[min(level, len(self.schedule) - 1)]

        now = time.time()
        unban_at = None if duration == -1 else now + duration * 60

        record = BanRecord(
            ip              = ip,
            banned_at       = now,
            ban_level       = level,
            duration_minutes= duration,
            unban_at        = unban_at,
            condition       = condition,
            rate            = rate,
            baseline        = baseline,
            active          = True,
        )
        self._bans[ip] = record

        # Advance offense count for next time
        self._offense_count[ip] = level + 1

        # Apply the iptables rule
        await self._iptables_drop(ip)

        logger.warning(
            f"BANNED {ip} | level={level} | duration={record.duration_label} | "
            f"rate={rate:.2f}/s | baseline={baseline:.2f}/s"
        )

        # Notify all callbacks (audit log, Slack)
        for cb in self._ban_callbacks:
            try:
                await cb(record)
            except Exception as e:
                logger.error(f"Ban callback error: {e}")

        return record

    # ── Unbanning ─────────────────────────────────────────────────────────────

    async def unban(self, ip: str) -> Optional[BanRecord]:
        """Remove iptables rule and mark ban as inactive."""
        record = self._bans.get(ip)
        if not record or not record.active:
            return None

        record.active = False
        await self._iptables_remove(ip)

        logger.info(f"UNBANNED {ip} | was level={record.ban_level}")

        for cb in self._unban_callbacks:
            try:
                await cb(record)
            except Exception as e:
                logger.error(f"Unban callback error: {e}")

        return record

    # ── iptables commands ─────────────────────────────────────────────────────

    async def _iptables_drop(self, ip: str) -> bool:
        """
        Add iptables rule: DROP all packets from this IP.
        We use -I (insert at top) so our rules take priority.

        First checks if the rule already exists to avoid duplicates.
        """
        try:
            # Check if rule already exists
            check = await asyncio.create_subprocess_exec(
                "iptables", "-C", "INPUT", "-s", ip, "-j", "DROP",
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            await check.wait()
            if check.returncode == 0:
                logger.debug(f"iptables DROP already exists for {ip}")
                return True

            # Rule doesn't exist yet — insert it
            proc = await asyncio.create_subprocess_exec(
                "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            _, stderr = await proc.communicate()

            if proc.returncode != 0:
                logger.error(f"iptables -I failed for {ip}: {stderr.decode()}")
                return False

            logger.info(f"iptables DROP rule added for {ip}")
            return True

        except FileNotFoundError:
            # iptables not installed — running in dev/test environment
            logger.warning(f"iptables not found — SIMULATION: would block {ip}")
            return True
        except Exception as e:
            logger.error(f"iptables error for {ip}: {e}")
            return False

    async def _iptables_remove(self, ip: str) -> bool:
        """Remove the DROP rule for an IP."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            _, stderr = await proc.communicate()

            if proc.returncode != 0:
                err = stderr.decode()
                # "no such rule" is fine — it was already removed somehow
                if "does a matching rule exist" in err or proc.returncode == 1:
                    logger.debug(f"iptables rule for {ip} already gone")
                    return True
                logger.error(f"iptables -D failed for {ip}: {err}")
                return False

            logger.info(f"iptables DROP rule removed for {ip}")
            return True

        except FileNotFoundError:
            logger.warning(f"iptables not found — SIMULATION: would unblock {ip}")
            return True
        except Exception as e:
            logger.error(f"iptables remove error for {ip}: {e}")
            return False