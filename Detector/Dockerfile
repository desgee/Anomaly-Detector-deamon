FROM python:3.11.9-slim

LABEL maintainer="HNG DevSecOps" \
      description="Anomaly detection daemon for cloud.ng" \
      version="1.0"

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iptables \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


COPY main.py      .
COPY monitor.py   .
COPY baseline.py  .
COPY detector.py  .
COPY blocker.py   .
COPY unbanner.py  .
COPY notifier.py  .
COPY dashboard.py .
COPY config.yaml  .


RUN mkdir -p /var/log/nginx /var/log/detector

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD curl --fail --silent http://localhost:8080/api/metrics || exit 1

ENTRYPOINT ["python", "main.py", "--config", "config.yaml"]