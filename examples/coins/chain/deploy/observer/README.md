# Coins Chain Observer

This directory runs the non-validator observer host:

- `coins-chain-indexer` serves the indexer API and built frontend.
- Prometheus scrapes validator and validator host metrics.
- Grafana provisions the Prometheus datasource and dashboards.

## Files

- `compose.yaml` starts the observer services.
- `prometheus.yml` contains validator and node-exporter scrape targets.
- `grafana/provisioning` provisions Grafana.
- `grafana/dashboards` contains dashboards loaded by Grafana.

## Prepare

Build the frontend and copy the production assets into `frontend/` on the
observer host:

```sh
cd examples/coins/frontend
npm ci
npm run build
```

Copy `examples/coins/frontend/dist` to the observer deploy directory as
`frontend`.

Edit `prometheus.yml` and replace the `validator-N-private-ip` placeholders with
the validator private network addresses.

Create `.env` next to `compose.yaml`:

```sh
COINS_INDEXER_IMAGE=nunchi-coins-indexer:latest
INDEXER_IDENTITY=<identity from narae.toml>
INDEXER_PARTICIPANTS=4
INDEXER_BIND=0.0.0.0
INDEXER_PORT=8080
PROMETHEUS_BIND=127.0.0.1
PROMETHEUS_PORT=9090
GRAFANA_BIND=127.0.0.1
GRAFANA_PORT=3000
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=<change-me>
```

## Run

```sh
docker load -i coins-chain-indexer.tar
docker compose up -d
```

If the host only has the legacy Compose binary:

```sh
docker-compose up -d
```
