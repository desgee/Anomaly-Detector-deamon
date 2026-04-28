import asyncio
import logging
import time

from blocker import Blocker

logger = logging.getLogger("unbanner")


class Unbanner:
    """
    Polls active bans and releases expired ones.

    Design choice: poll every 30 seconds rather than scheduling individual
    timers per ban. This is simpler — we don't need to worry about timer
    cleanup, and 30 seconds is well within the precision needed (bans are
    in minutes, not seconds).
    """

    def __init__(self, blocker: Blocker):
        self.blocker = blocker
        self._poll_interval = 30  # check every 30 seconds

    async def run(self):
        """Main loop — runs forever, checking for expired bans."""
        logger.info("Unbanner started — polling every 30s")
        while True:
            await asyncio.sleep(self._poll_interval)
            await self._release_expired()

    async def _release_expired(self):
        """Check all active bans and unban any that have expired."""
        now = time.time()

        # Get a snapshot of active bans to iterate over
        active_bans = self.blocker.get_active_bans()

        for record in active_bans:
            # Permanent bans (unban_at = None) are never auto-released
            if record.unban_at is None:
                continue

            # Check if this ban has expired
            if now >= record.unban_at:
                elapsed_minutes = (now - record.banned_at) / 60
                logger.info(
                    f"Ban expired for {record.ip} | "
                    f"was level={record.ban_level} | "
                    f"elapsed={elapsed_minutes:.1f} min"
                )
                await self.blocker.unban(record.ip)