#!/bin/sh
set -eu

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  apt-transport-https \
  ca-certificates \
  gnupg \
  prometheus \
  wget

mkdir -p /etc/apt/keyrings
wget -O /etc/apt/keyrings/grafana.asc https://apt.grafana.com/gpg-full.key
chmod 644 /etc/apt/keyrings/grafana.asc
echo "deb [signed-by=/etc/apt/keyrings/grafana.asc] https://apt.grafana.com stable main" >/etc/apt/sources.list.d/grafana.list

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends grafana

cat >/tmp/prometheus.yml <<'EOF'
global:
  scrape_interval: 5s

scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets:
          - 127.0.0.1:9090
EOF

mkdir -p /etc/grafana/provisioning/datasources
cat >/etc/grafana/provisioning/datasources/prometheus.yml <<'EOF'
apiVersion: 1

datasources:
  - name: Prometheus
    uid: prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9000
    isDefault: true
EOF

mkdir -p /etc/grafana/provisioning/dashboards
cat >/etc/grafana/provisioning/dashboards/coins-chain.yml <<'EOF'
apiVersion: 1

providers:
  - name: Coins Chain
    orgId: 1
    folder: ""
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /workspace
EOF

prometheus_pid=
if wget -q --spider http://127.0.0.1:9000/-/ready; then
  echo "Using existing Prometheus at 127.0.0.1:9000"
else
  prometheus \
    --config.file=/tmp/prometheus.yml \
    --storage.tsdb.path=/tmp/prometheus-data \
    --web.listen-address=0.0.0.0:9000 &
  prometheus_pid=$!
fi

trap 'if [ -n "$prometheus_pid" ]; then kill "$prometheus_pid" 2>/dev/null || true; fi' INT TERM EXIT

if command -v grafana-server >/dev/null 2>&1; then
  GF_PATHS_PROVISIONING=/etc/grafana/provisioning \
  grafana-server \
    --homepath=/usr/share/grafana \
    --config=/etc/grafana/grafana.ini \
    --packaging=deb
else
  GF_PATHS_PROVISIONING=/etc/grafana/provisioning \
  grafana server \
    --homepath=/usr/share/grafana \
    --config=/etc/grafana/grafana.ini \
    --packaging=deb
fi
