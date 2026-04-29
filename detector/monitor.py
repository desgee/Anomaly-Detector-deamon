import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("monitor")


# ── Data class for a single HTTP request ─────────────────────────────────────

@dataclass
class LogEntry:
    
    source_ip: str
    timestamp: float      # Unix epoch (seconds since 1970)
    method: str           # GET, POST, etc.
    path: str             # /index.php, /remote.php/dav, etc.
    status: int           # 200, 404, 500, etc.
    response_size: int    # bytes sent back to client


# ── JSON line parser ──────────────────────────────────────────────────────────

def parse_line(line: str) -> Optional[LogEntry]:
    """
    Turn one raw JSON log line into a LogEntry.
    Returns None if the line is blank or unparseable.

    Our Nginx log format looks like:
    {"source_ip":"1.2.3.4","timestamp":1714123456.789,"method":"GET",...}
    """
    line = line.strip()
    if not line:
        return None  # blank line — skip it

    try:
        data = json.loads(line)

        # Pull out source_ip — try several field names in case config differs
        ip = (data.get("source_ip")
              or data.get("remote_addr")
              or "0.0.0.0")

        # Timestamp: Nginx gives us milliseconds-since-epoch as a float
        ts_raw = data.get("timestamp") or data.get("msec") or time.time()
        try:
            ts = float(ts_raw)
            # Nginx $msec is already seconds.milliseconds — if > year 3000 it's ms
            if ts > 9_999_999_999:
                ts = ts / 1000.0
        except (ValueError, TypeError):
            ts = time.time()

        method = data.get("method") or data.get("request_method") or "UNKNOWN"
        path   = data.get("path")   or data.get("uri") or data.get("request_uri") or "/"
        status = int(data.get("status", 0))
        size   = int(data.get("response_size") or data.get("body_bytes_sent") or 0)

        return LogEntry(
            source_ip=ip,
            timestamp=ts,
            method=method,
            path=path,
            status=status,
            response_size=size,
        )

    except (json.JSONDecodeError, ValueError, TypeError, KeyError) as exc:
        # Bad line — log at debug level and move on
        logger.debug(f"Could not parse log line: {exc} | line={line[:100]}")
        return None


# ── The monitor class ─────────────────────────────────────────────────────────

class LogMonitor:
    """
    Tails the Nginx access log file in real time.

    How it works:
    1. Open the file and seek to the END (we don't replay old history)
    2. Every 100ms, try to read a new line
    3. If we get one, parse it and put it on the queue
    4. If no new line, check for log rotation and wait briefly

    Log rotation detection:
    - Nginx (or logrotate) may rename the current log file and create a new one
    - We detect this by watching the file's inode number
    - If the inode changes, we close and reopen the file
    """

    def __init__(self, log_path: str, queue: asyncio.Queue):
        self.log_path = log_path
        self.queue = queue
        self._running = False
        self._file = None
        self._inode: Optional[int] = None

    async def start(self):
        """Main entry point — runs forever until stop() is called."""
        self._running = True
        logger.info(f"LogMonitor starting — watching {self.log_path}")
        await self._tail_loop()

    def stop(self):
        self._running = False

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _wait_for_file(self):
        """Block until the log file exists. Useful on first startup."""
        while self._running and not os.path.exists(self.log_path):
            logger.info(f"Waiting for log file: {self.log_path}")
            await asyncio.sleep(2)

    async def _open_file(self, seek_to_end: bool = True):
        """Open the log file. On first open, seek to end to skip old lines."""
        f = open(self.log_path, "r", encoding="utf-8", errors="replace")
        stat = os.fstat(f.fileno())
        self._inode = stat.st_ino
        if seek_to_end:
            f.seek(0, 2)  # seek to end of file
        logger.info(f"Opened log file (inode={self._inode}, seek_end={seek_to_end})")
        return f

    async def _rotation_happened(self) -> bool:
        """
        Check if the log file was rotated (replaced with a new file).
        We do this by comparing the inode of the path vs. our open file.
        """
        try:
            stat = os.stat(self.log_path)
            # Different inode = it's a new file
            if stat.st_ino != self._inode:
                return True
            # If current file size < our position, it was truncated
            if self._file and stat.st_size < self._file.tell():
                return True
        except OSError:
            pass
        return False

    async def _tail_loop(self):
        """
        Core loop: wait for file → open → read lines forever.
        """
        await self._wait_for_file()
        self._file = await self._open_file(seek_to_end=True)

        # How often we check for rotation (every N no-data polls)
        rotation_check_every = 50  # = ~5 seconds at 100ms poll
        polls_since_data = 0

        while self._running:
            line = self._file.readline()

            if line:
                # Got a new log line — parse and queue it
                polls_since_data = 0
                entry = parse_line(line)
                if entry:
                    await self.queue.put(entry)
            else:
                # No new data yet — sleep briefly
                await asyncio.sleep(0.1)
                polls_since_data += 1

                # Every ~5 seconds of no data, check for rotation
                if polls_since_data >= rotation_check_every:
                    polls_since_data = 0
                    if await self._rotation_happened():
                        logger.info("Log rotation detected — reopening file")
                        self._file.close()
                        await self._wait_for_file()
                        # New file: start from beginning (don't skip — it's new)
                        self._file = await self._open_file(seek_to_end=False)