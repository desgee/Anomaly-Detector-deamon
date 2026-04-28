# 🛡️ HNG Anomaly Detection Engine

Real-time HTTP traffic anomaly detection and automatic IP blocking for **cloud.ng** — HNG's Nextcloud-powered cloud storage platform.

---

## 📡 Live Links

| | |
|---|---|
| **Server IP** | `YOUR_SERVER_IP` |
| **Metrics Dashboard** | `http://YOUR_SERVER_IP:8080` |
| **Nextcloud** | `http://YOUR_SERVER_IP` (IP only, no port) |
| **GitHub** | `https://github.com/YOUR_USERNAME/DevSecOps-Anomaly-Detector` |
| **Blog Post** | `https://YOUR_BLOG_POST_URL` |

---

## 🗣️ Language: Python

Chosen because:
- `asyncio` lets one process tail logs, serve the dashboard, call Slack, and run iptables — all without threads
- `collections.deque` gives O(1) append and O(k) eviction — exactly what a sliding window needs
- The statistics (mean, stddev, z-score) are 5 lines of pure math — no libraries needed
- `aiohttp` serves the live dashboard without blocking the detection loop

---

## 🪟 How the Sliding Window Works

Every HTTP request that arrives in the Nginx log gets its **timestamp appended to a deque**:

```
Per-IP deque:    [1714100.1, 1714100.3, 1714100.6, 1714101.0, ...]
Global deque:    [1714100.1, 1714100.2, 1714100.3, ...]
```

**Eviction** happens from the LEFT every time we read the rate:

```python
cutoff = now - 60   # 60 seconds ago

while deque and deque[0] < cutoff:
    deque.popleft()   # remove expired timestamps
```

This works because timestamps are always appended newest-on-right, so the oldest is always on the left. We just pop from the left until we hit something recent enough.

**Rate calculation:**

```python
rate = len(deque) / 60    # requests per second over the window
```

This gives a true continuous sliding window. If 100 requests arrived 30 seconds ago and none since, the rate is `100/60 = 1.67 req/s`. One second later, those same 100 requests are now `1.67 req/s` — the window has slid forward.

---

## 📊 How the Baseline Works

**Window size:** 30 minutes of per-second traffic counts.

Every second of data is stored as `(timestamp, request_count, error_count)` in a rolling deque. Entries older than 30 minutes are evicted from the left.

**Recalculation interval:** Every 60 seconds, mean and standard deviation are recomputed:

```python
mean     = sum(counts) / n
variance = sum((x - mean)**2 for x in counts) / n
stddev   = sqrt(variance)
```

**Hourly slots:** The engine also keeps per-calendar-hour buckets. If the current hour has 60+ seconds of data, it is preferred over the 30-minute rolling window. This handles diurnal patterns — 2am traffic looks different from 2pm traffic.

**Floor values:** To prevent false positives at startup:
```yaml
floor_mean:   0.1    # minimum effective mean (req/s)
floor_stddev: 0.05   # minimum effective stddev
```
These apply when computed values fall below them.

---

## 🚨 How Anomaly Detection Works

An IP (or global traffic) is flagged when **either** condition fires:

```
z-score  = (current_rate - baseline_mean) / baseline_stddev

Condition 1: z-score > 3.0          (statistically 3 stddevs above normal)
Condition 2: rate > 5 × baseline_mean  (simple 5x multiplier check)
```

Whichever fires first triggers the response. Both can fire together.

**Error surge tightening:** If an IP's 4xx/5xx rate exceeds 3× the baseline error rate, it's probably scanning for vulnerabilities. The z-score threshold is halved (`3.0 × 0.5 = 1.5`) so it gets caught sooner.

---

## 🔨 Ban Schedule (Progressive Backoff)

| Offence | Ban Duration |
|---|---|
| 1st | 10 minutes |
| 2nd | 30 minutes |
| 3rd | 2 hours |
| 4th+ | **Permanent** |

The unbanner polls every 30 seconds and releases expired bans automatically. Permanent bans require manual removal with `iptables -D INPUT -s <ip> -j DROP`.

---

## 🚀 Setup: Fresh VPS to Running Stack

### 1. Requirements
- Ubuntu 22.04 LTS
- Minimum 2 vCPU, 2 GB RAM
- Ports **80** and **8080** open in your firewall/security group

### 2. Install Docker

```bash
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
newgrp docker

# Install Docker Compose plugin
sudo apt-get install -y docker-compose-plugin

# Verify
docker --version
docker compose version
```

### 3. Clone the repo

```bash
git clone https://github.com/YOUR_USERNAME/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### 4. Configure environment

```bash
cp .env.example .env
nano .env
```

Fill in:
- `SERVER_IP` — your VPS public IP
- `NC_ADMIN_PASS` — strong Nextcloud admin password
- `POSTGRES_PASSWORD` — strong database password
- `SLACK_WEBHOOK_URL` — your Slack incoming webhook URL

### 5. Start the stack

```bash
docker compose up -d --build
```

### 6. Check everything is running

```bash
# All 4 containers should show "running" or "healthy"
docker compose ps

# Watch the detector process log lines in real time
docker compose logs -f detector

# Confirm Nginx is writing JSON logs
docker compose exec nginx tail -f /var/log/nginx/hng-access.log

# Check the metrics API responds
curl http://localhost:8080/api/metrics
```

### 7. Nextcloud first-time setup

Visit `http://YOUR_SERVER_IP` in your browser and complete the setup wizard.
Use the admin username and password from your `.env` file.

---

## 📋 Audit Log Format

Every ban, unban, and baseline recalculation is written to `/var/log/detector/audit.log`:

```
[2026-04-26T10:00:00Z] BAN 203.0.113.42 | z-score=8.42 > 3.0 | rate=47.320 | baseline=0.850 | duration=10min
[2026-04-26T10:10:05Z] UNBAN 203.0.113.42 | was_level=0 | elapsed=10.1min | original_condition=z-score=8.42 > 3.0
[2026-04-26T10:11:00Z] BASELINE_RECALC - | source=rolling_30min | mean=0.9200 | stddev=0.1800 | samples=660
```

On the host:
```bash
tail -f /var/log/detector/audit.log
```

---

## 📁 Project Structure

```
hng-anomaly-detector/
├── .env                    ← your secrets (never commit this)
├── .env.example            ← template with placeholder values
├── .gitignore
├── docker-compose.yml      ← wires all 4 services together
├── README.md
│
├── detector/               ← the daemon (only service with a Dockerfile)
│   ├── Dockerfile
│   ├── requirements.txt    ← pyyaml, aiohttp, psutil
│   ├── config.yaml         ← all thresholds in one place
│   ├── main.py             ← entry point, wires everything together
│   ├── monitor.py          ← tails and parses the nginx log
│   ├── baseline.py         ← rolling 30-min baseline engine
│   ├── detector.py         ← sliding windows + anomaly detection
│   ├── blocker.py          ← iptables ban management
│   ├── unbanner.py         ← auto-releases expired bans
│   ├── notifier.py         ← Slack alerts
│   └── dashboard.py        ← live metrics web UI on port 8080
│
├── nginx/
│   └── nginx.conf          ← JSON logs + X-Forwarded-For
│
├── docs/
│   └── architecture.png
│
└── screenshots/
    ├── Tool-running.png
    ├── Ban-slack.png
    ├── Unban-slack.png
    ├── Global-alert-slack.png
    ├── Iptables-banned.png
    ├── Audit-log.png
    └── Baseline-graph.png
```

---

## ⚙️ Configuration Reference

All thresholds live in `detector/config.yaml`. Nothing is hardcoded in Python.

| Key | Default | What it controls |
|---|---|---|
| `sliding_window.seconds` | 60 | How far back the deque window looks |
| `baseline.rolling_window_minutes` | 30 | Rolling window for baseline computation |
| `baseline.recalc_interval_seconds` | 60 | How often baseline is recalculated |
| `baseline.floor_mean` | 0.1 | Minimum baseline mean — prevents false positives at startup |
| `baseline.floor_stddev` | 0.05 | Minimum baseline stddev |
| `anomaly.z_score_threshold` | 3.0 | Z-score to trigger an alert |
| `anomaly.rate_multiplier` | 5.0 | Rate × mean to trigger an alert |
| `anomaly.error_rate_multiplier` | 3.0 | Error surge detection multiplier |
| `anomaly.error_tightening` | 0.5 | How much to tighten threshold on error surge |
| `anomaly.flag_cooldown_seconds` | 30 | Minimum seconds between flagging the same IP |
| `blocking.ban_schedule_minutes` | [10,30,120,-1] | Progressive ban durations |
| `dashboard.port` | 8080 | Dashboard port |


"""
baseline.py — Rolling Baseline Engine
======================================
This is the "long-term memory" of the detector.

It answers the question: "What does normal traffic look like right now?"

How it works:
  1. Every second of traffic, we record how many requests arrived in that second
  2. We keep a 30-minute rolling window of these per-second counts
  3. Every 60 seconds, we compute mean and standard deviation from that window
  4. We also bucket counts by calendar hour — so if 8pm traffic is typically
     heavier than 2am traffic, we prefer the current hour's data

Why this matters:
  The anomaly detector compares the CURRENT rate against this baseline.
  Without a rolling baseline, we'd either hardcode a threshold (bad — traffic
  patterns change) or compare against all-time history (also bad — yesterday's
  DDoS would skew the numbers).
"""

"""
blocker.py — IP Blocker
========================
Manages iptables DROP rules for banned IPs.

When an IP is flagged as anomalous, this module:
  1. Looks up how many times this IP has been banned before (ban level)
  2. Picks the right ban duration from the schedule (10m, 30m, 2h, permanent)
  3. Runs: iptables -I INPUT -s <ip> -j DROP
  4. Records the ban so the unbanner knows when to release it

Why iptables?
  It works at the kernel level — banned IPs can't even complete a TCP handshake.
  Their packets are dropped before Nginx even sees them.

Why -I (insert) instead of -A (append)?
  -I inserts at the top of the chain. That way our DROP rules are checked
  first, before any ACCEPT rules further down.
"""

"""
dashboard.py — Live Metrics Web Dashboard
==========================================
Serves a web page at http://<your-server>:8080 that shows:
  - Currently banned IPs
  - Global requests/second
  - Top 10 source IPs
  - CPU and memory usage
  - Current baseline mean and stddev
  - Detector uptime

The page polls /api/metrics every 3 seconds and updates itself
without a full page reload (simple fetch + DOM update).

Two endpoints:
  GET /          → The HTML dashboard page
  GET /api/metrics → JSON blob with all current metrics
"""

"""
main.py — Orchestrator
========================
This is the entry point. It wires together all the other modules:

  LogMonitor  →  queue  →  AnomalyDetector
                               │
                    ┌──────────┴───────────┐
                    ▼                      ▼
               Blocker              BaselineEngine
                    │
                    ├── AuditLogger
                    ├── SlackNotifier
                    └── Unbanner (auto-release)

  Dashboard reads from the shared DetectorState.

How to run:
  python main.py --config config.yaml

The program runs forever until you press Ctrl+C.
"""


"""
monitor.py — Log Monitor
========================
Reads the Nginx JSON access log line by line, forever.
Think of this as the "eyes" of the detector — it sees every
HTTP request the moment Nginx records it.

It handles:
  - Waiting for the log file to appear (in case Nginx hasn't started yet)
  - Log rotation (when the file gets replaced/renamed, we reopen it)
  - Parsing each JSON line into a clean Python object
  - Putting parsed entries onto an asyncio queue for the detector to consume
"""


"""
notifier.py — Slack Notifications
====================================
Sends alerts to a Slack channel via an Incoming Webhook URL.

Three types of alerts:
  1. Ban alert    — when an IP gets blocked
  2. Unban alert  — when a ban expires and the IP is released
  3. Global alert — when a global traffic spike is detected (no single IP blocked)

The webhook URL is read from config (which substitutes ${SLACK_WEBHOOK_URL}
from the environment). If not configured, alerts are logged to stdout instead.

Alert format includes:
  - The condition that fired (z-score, rate multiplier, or error surge)
  - Current rate vs. baseline
  - Timestamp
  - Ban duration (for ban alerts)
"""


"""
unbanner.py — Automatic Ban Release
=====================================
Runs as a background task, waking up every 30 seconds to check
whether any active bans have expired.

The ban schedule creates a backoff effect:
  - First time caught: banned for 10 minutes
  - Gets caught again: banned for 30 minutes
  - Again: 2 hours
  - Again: permanent (never auto-released)

For permanent bans: the unban_at field is None, so we skip them.
Only a manual iptables -D command can remove a permanent ban.
"""

# =============================================================================
# nginx.conf — HNG cloud.ng Reverse Proxy
#
# Two jobs:
#   1. Forward all HTTP traffic to the Nextcloud container
#   2. Write every request as a JSON line to /var/log/nginx/hng-access.log
#      (which is the shared HNG-nginx-logs Docker volume)
#
# The detector reads these JSON lines in real time.
# =============================================================================


# ─────────────────────────────────────────────────────────────────────────────
# docker-compose.yml — HNG cloud.ng Full Stack
#
# Four services, one network, three volumes.
#
# Service startup order:
#   db → nextcloud → nginx → detector
#
# The key constraint from the brief:
#   The shared volume MUST be named "HNG-nginx-logs" (exact spelling).
#   nginx  → writes logs to it
#   nextcloud → mounts it read-only
#   detector  → mounts it read-only
# ─────────────────────────────────────────────────────────────────────────────

# ── Named volumes ─────────────────────────────────────────────────────────────
# Named volumes persist data even when containers are stopped or removed.
# They are managed by Docker and stored in /var/lib/docker/volumes/ on the host.

