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