

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

import aiohttp
import psutil
from aiohttp import web

logger = logging.getLogger("dashboard")

# When the detector started — used to compute uptime
_STARTED_AT = time.time()


def _uptime() -> str:
    """Returns uptime as HH:MM:SS string."""
    elapsed = int(time.time() - _STARTED_AT)
    h, rem = divmod(elapsed, 3600)
    m, s   = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


# ── HTML page ─────────────────────────────────────────────────────────────────
# Kept in one string here so the whole project is self-contained with no
# template files to manage.

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>HNG Anomaly Detector</title>
<style>
  :root {
    --bg: #0a0e17;
    --surface: #111827;
    --card: #1a2235;
    --border: #2a3a55;
    --accent: #00d4ff;
    --danger: #ff4757;
    --warn: #ffa502;
    --ok: #2ed573;
    --text: #e2e8f0;
    --muted: #64748b;
    --mono: 'Courier New', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; }

  header {
    padding: 16px 24px;
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; justify-content: space-between;
    background: var(--surface);
  }
  .logo { font-size: 1.1rem; font-weight: 700; }
  .logo span { color: var(--accent); }
  .live { display: flex; align-items: center; gap: 8px; font-size: .8rem; color: var(--ok); }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok);
         animation: pulse 1.5s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }

  main { padding: 20px 24px; max-width: 1300px; margin: 0 auto; }

  /* Top stats row */
  .stats { display: grid; grid-template-columns: repeat(4,1fr); gap: 14px; margin-bottom: 20px; }
  .stat {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px 18px;
  }
  .stat-label { font-size: .7rem; color: var(--muted); text-transform: uppercase;
                letter-spacing: .08em; margin-bottom: 8px; }
  .stat-value { font-size: 1.9rem; font-weight: 700; }
  .stat-sub { font-size: .72rem; color: var(--muted); margin-top: 4px; }
  .accent { color: var(--accent); }
  .danger { color: var(--danger); }
  .ok    { color: var(--ok); }
  .warn  { color: var(--warn); }

  /* Two-column grid */
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }

  .panel {
    background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    overflow: hidden;
  }
  .panel-head {
    padding: 12px 18px; border-bottom: 1px solid var(--border);
    font-size: .8rem; color: var(--accent); font-weight: 600;
    text-transform: uppercase; letter-spacing: .08em;
    display: flex; justify-content: space-between; align-items: center;
  }
  .panel-body { padding: 0; max-height: 300px; overflow-y: auto; }

  /* Ban list */
  .ban-row {
    display: grid; grid-template-columns: 1fr auto;
    padding: 11px 18px; border-bottom: 1px solid rgba(42,58,85,.5);
    gap: 10px; align-items: center;
  }
  .ban-row:last-child { border-bottom: none; }
  .ban-ip { font-family: var(--mono); font-size: .85rem; color: var(--danger); }
  .ban-cond { font-size: .7rem; color: var(--muted); margin-top: 2px; }
  .ban-badge {
    font-family: var(--mono); font-size: .7rem; padding: 3px 8px;
    border-radius: 4px; white-space: nowrap;
    background: rgba(255,71,87,.12); color: var(--danger);
    border: 1px solid rgba(255,71,87,.3);
  }
  .ban-badge.perm { background: rgba(255,71,87,.25); }

  /* Top IPs list */
  .ip-row {
    display: grid; grid-template-columns: 20px 1fr auto;
    gap: 10px; padding: 10px 18px; border-bottom: 1px solid rgba(42,58,85,.5);
    align-items: center;
  }
  .ip-row:last-child { border-bottom: none; }
  .ip-rank { font-size: .75rem; color: var(--muted); text-align: right; }
  .ip-addr { font-family: var(--mono); font-size: .82rem; }
  .ip-bar-wrap { display: flex; align-items: center; gap: 8px; }
  .ip-bar { width: 80px; height: 4px; background: var(--border); border-radius: 2px; }
  .ip-bar-fill { height: 100%; background: var(--accent); border-radius: 2px; transition: width .5s; }
  .ip-rate { font-family: var(--mono); font-size: .75rem; color: var(--accent); min-width: 55px; text-align: right; }

  /* Baseline stats */
  .bl-grid { display: grid; grid-template-columns: 1fr 1fr; }
  .bl-cell { padding: 16px 18px; border-right: 1px solid var(--border);
             border-bottom: 1px solid var(--border); }
  .bl-cell:nth-child(even) { border-right: none; }
  .bl-cell:nth-last-child(-n+2) { border-bottom: none; }
  .bl-label { font-size: .68rem; color: var(--muted); text-transform: uppercase;
              letter-spacing: .08em; margin-bottom: 6px; }
  .bl-val { font-size: 1.3rem; font-weight: 700; color: var(--accent); font-family: var(--mono); }
  .bl-source { font-size: .68rem; color: var(--muted); margin-top: 4px; }

  /* Resource bars */
  .res-row { padding: 14px 18px; border-bottom: 1px solid rgba(42,58,85,.5);
             display: flex; align-items: center; gap: 12px; }
  .res-row:last-child { border-bottom: none; }
  .res-label { font-size: .75rem; color: var(--muted); min-width: 60px; }
  .res-bar { flex: 1; height: 6px; background: var(--border); border-radius: 3px; overflow: hidden; }
  .res-fill { height: 100%; border-radius: 3px; transition: width .6s; }
  .res-fill.cpu { background: linear-gradient(90deg, var(--accent), var(--ok)); }
  .res-fill.mem { background: linear-gradient(90deg, var(--warn), var(--danger)); }
  .res-val { font-family: var(--mono); font-size: .8rem; min-width: 44px; text-align: right; }

  .empty { text-align: center; padding: 30px; color: var(--muted); font-size: .85rem; }

  @media (max-width: 800px) {
    .stats { grid-template-columns: repeat(2,1fr); }
    .grid  { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>
<header>
  <div class="logo">HNG <span>Anomaly</span> Detector — cloud.ng</div>
  <div class="live"><span class="dot"></span> LIVE — refreshes every 3s</div>
</header>

<main>
  <div class="stats">
    <div class="stat">
      <div class="stat-label">Banned IPs</div>
      <div class="stat-value danger" id="val-banned">0</div>
      <div class="stat-sub" id="sub-banned">No active bans</div>
    </div>
    <div class="stat">
      <div class="stat-label">Global req/s</div>
      <div class="stat-value accent" id="val-rps">0.00</div>
      <div class="stat-sub">60-second window</div>
    </div>
    <div class="stat">
      <div class="stat-label">CPU Usage</div>
      <div class="stat-value ok" id="val-cpu">0%</div>
      <div class="stat-sub" id="sub-cpu">—</div>
    </div>
    <div class="stat">
      <div class="stat-label">Memory</div>
      <div class="stat-value warn" id="val-mem">0%</div>
      <div class="stat-sub" id="sub-mem">—</div>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <div class="panel-head">
        <span>Active Bans</span>
        <span id="ban-count" style="color:var(--muted);font-weight:400">0</span>
      </div>
      <div class="panel-body" id="ban-list">
        <div class="empty">No active bans — all clear</div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head">Top 10 Source IPs</div>
      <div class="panel-body" id="ip-list">
        <div class="empty">No traffic recorded yet</div>
      </div>
    </div>
  </div>

  <div class="grid">
    <div class="panel">
      <div class="panel-head">
        <span>Baseline</span>
        <span id="bl-source" style="color:var(--muted);font-weight:400">—</span>
      </div>
      <div class="bl-grid">
        <div class="bl-cell">
          <div class="bl-label">Effective Mean</div>
          <div class="bl-val" id="bl-mean">—</div>
          <div class="bl-source">req/s</div>
        </div>
        <div class="bl-cell">
          <div class="bl-label">Std Dev</div>
          <div class="bl-val" id="bl-stddev">—</div>
          <div class="bl-source">req/s</div>
        </div>
        <div class="bl-cell">
          <div class="bl-label">Samples</div>
          <div class="bl-val" id="bl-n">—</div>
          <div class="bl-source">seconds</div>
        </div>
        <div class="bl-cell">
          <div class="bl-label">Uptime</div>
          <div class="bl-val" id="bl-uptime" style="font-size:1rem">—</div>
          <div class="bl-source">hh:mm:ss</div>
        </div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-head">System Resources</div>
      <div class="panel-body">
        <div class="res-row">
          <span class="res-label">CPU</span>
          <div class="res-bar"><div class="res-fill cpu" id="cpu-bar" style="width:0%"></div></div>
          <span class="res-val" id="cpu-val">0%</span>
        </div>
        <div class="res-row">
          <span class="res-label">Memory</span>
          <div class="res-bar"><div class="res-fill mem" id="mem-bar" style="width:0%"></div></div>
          <span class="res-val" id="mem-val">0%</span>
        </div>
        <div class="res-row" style="flex-direction:column;align-items:flex-start;gap:4px">
          <span class="res-label">Total bans issued</span>
          <span class="res-val" id="total-bans" style="text-align:left;font-size:.95rem">0</span>
        </div>
        <div class="res-row" style="flex-direction:column;align-items:flex-start;gap:4px">
          <span class="res-label">Log lines parsed</span>
          <span class="res-val" id="lines-read" style="text-align:left;font-size:.95rem">0</span>
        </div>
      </div>
    </div>
  </div>
</main>

<script>
async function refresh() {
  let d;
  try {
    const r = await fetch('/api/metrics');
    d = await r.json();
  } catch(e) { return; }

  // Header stats
  const bans = d.active_bans || [];
  document.getElementById('val-banned').textContent = bans.length;
  document.getElementById('sub-banned').textContent =
    bans.length ? bans.map(b => b.ip).join(', ') : 'No active bans';
  document.getElementById('val-rps').textContent = (d.global_rps||0).toFixed(2);

  const cpu = d.cpu_pct||0, mem = d.mem_pct||0;
  document.getElementById('val-cpu').textContent = cpu.toFixed(1)+'%';
  document.getElementById('val-mem').textContent = mem.toFixed(1)+'%';
  document.getElementById('sub-cpu').textContent = (d.cpu_count||0)+' cores';
  document.getElementById('sub-mem').textContent =
    (d.mem_used_mb||0)+' / '+(d.mem_total_mb||0)+' MB';
  document.getElementById('cpu-bar').style.width = cpu+'%';
  document.getElementById('mem-bar').style.width = mem+'%';
  document.getElementById('cpu-val').textContent = cpu.toFixed(1)+'%';
  document.getElementById('mem-val').textContent = mem.toFixed(1)+'%';

  // Baseline
  const bl = d.baseline||{};
  document.getElementById('bl-mean').textContent   = (bl.mean||0).toFixed(3);
  document.getElementById('bl-stddev').textContent = (bl.stddev||0).toFixed(3);
  document.getElementById('bl-n').textContent      = (bl.sample_count||0).toLocaleString();
  document.getElementById('bl-source').textContent = bl.source||'—';
  document.getElementById('bl-uptime').textContent = d.uptime||'—';
  document.getElementById('ban-count').textContent = bans.length;
  document.getElementById('total-bans').textContent = (d.total_bans||0).toLocaleString();
  document.getElementById('lines-read').textContent = (d.lines_read||0).toLocaleString();

  // Ban list
  const banEl = document.getElementById('ban-list');
  if (bans.length === 0) {
    banEl.innerHTML = '<div class="empty">No active bans — all clear</div>';
  } else {
    banEl.innerHTML = bans.map(b => {
      const perm = b.duration_minutes === -1;
      const dur  = perm ? 'PERMANENT' : b.duration_minutes + 'm';
      return `<div class="ban-row">
        <div>
          <div class="ban-ip">&#x26D4; ${b.ip}</div>
          <div class="ban-cond">${b.condition||''}</div>
        </div>
        <span class="ban-badge ${perm?'perm':''}">${dur}</span>
      </div>`;
    }).join('');
  }

  // Top IPs
  const ipEl  = document.getElementById('ip-list');
  const tops  = d.top_ips||[];
  const maxR  = tops.length ? Math.max(...tops.map(x=>x[1]),0.01) : 0.01;
  if (tops.length === 0) {
    ipEl.innerHTML = '<div class="empty">No traffic yet</div>';
  } else {
    ipEl.innerHTML = tops.map(([ip,rate],i) => {
      const pct = Math.min(100,(rate/maxR)*100);
      return `<div class="ip-row">
        <span class="ip-rank">${i+1}</span>
        <span class="ip-addr">${ip}</span>
        <div class="ip-bar-wrap">
          <div class="ip-bar"><div class="ip-bar-fill" style="width:${pct}%"></div></div>
          <span class="ip-rate">${rate.toFixed(2)}/s</span>
        </div>
      </div>`;
    }).join('');
  }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>"""


class Dashboard:
    """
    Minimal aiohttp web server.

    GET /             → the HTML dashboard
    GET /api/metrics  → JSON metrics for the dashboard to consume
    """

    def __init__(self, cfg: dict, state):
        dc = cfg.get("dashboard", {})
        self.host  = dc.get("host", "0.0.0.0")
        self.port  = dc.get("port", 8080)
        self.state = state   # shared DetectorState object
        self._runner = None

    async def start(self):
        app = web.Application()
        app.router.add_get("/",            self._index)
        app.router.add_get("/api/metrics", self._metrics)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        logger.info(f"Dashboard running at http://{self.host}:{self.port}/")

    async def stop(self):
        if self._runner:
            await self._runner.cleanup()

    async def _index(self, _request):
        return web.Response(
            text=DASHBOARD_HTML,
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )

    async def _metrics(self, _request):
        s = self.state

        # Active bans
        bans = [
            {
                "ip":               r.ip,
                "banned_at":        r.banned_at,
                "duration_minutes": r.duration_minutes,
                "ban_level":        r.ban_level,
                "condition":        r.condition,
                "rate":             r.rate,
                "baseline":         r.baseline,
                "unban_at":         r.unban_at,
            }
            for r in s.blocker.get_active_bans()
        ]

        # Top IPs from the sliding window
        top_ips = await s.tracker.get_top_ips(10)

        # Global rate
        global_rps = await s.tracker.get_global_rate()

        # System metrics
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory()

        # Baseline
        snap = s.baseline.current

        payload = {
            "uptime":      _uptime(),
            "active_bans": bans,
            "global_rps":  global_rps,
            "top_ips":     top_ips,
            "cpu_pct":     cpu,
            "cpu_count":   psutil.cpu_count(),
            "mem_pct":     mem.percent,
            "mem_used_mb": round(mem.used  / 1024 / 1024),
            "mem_total_mb":round(mem.total / 1024 / 1024),
            "baseline": {
                "mean":         snap.mean,
                "stddev":       snap.stddev,
                "error_mean":   snap.error_mean,
                "sample_count": snap.sample_count,
                "source":       snap.source,
                "computed_at":  snap.computed_at,
            },
            "lines_read":  s.lines_read,
            "total_bans":  s.total_bans,
        }

        return web.Response(
            text=json.dumps(payload),
            content_type="application/json",
            headers={"Cache-Control": "no-store", "Access-Control-Allow-Origin": "*"},
        )