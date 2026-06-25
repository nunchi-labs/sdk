# Coins Chain Monitoring

This directory contains a sample Grafana dashboard for a local `coins-chain`
testnet. It is intended as a lightweight example for viewing metrics exposed by
`coins-chain-node`.

The setup starts Prometheus and Grafana in a Docker container, provisions a
Prometheus datasource, and automatically loads `dashboard.json` into Grafana.

## Files

- `create.sh` starts the monitoring container.
- `run.sh` installs and starts Prometheus and Grafana inside the container.
- `dashboard.json` is the sample Grafana dashboard.

## Running

Start the `coins-chain` testnet first so that node metrics are available on the
host. Then run the monitoring container from this directory:

```sh
cd examples/coins-chain/monitoring
sh create.sh
```

`create.sh` stops and removes any existing container named `monitoring` before
starting a new one. The container is run with `-it`, so the current terminal
stays attached to Grafana.

Open Grafana at:

```text
http://localhost:3000
```

The default Grafana credentials for the packaged install are usually:

```text
admin / admin
```

Grafana should automatically contain:

- a Prometheus datasource named `Prometheus`
- a dashboard named `Coins Chain Common Metrics`

## Ports And Addresses

The monitoring container uses Docker host networking:

```sh
--network host
```

The scripts currently use these ports:

- `3000`: Grafana
- `9000`: Prometheus web UI and Grafana datasource URL
- `9090`: local `coins-chain-node` metrics endpoint scraped by Prometheus

Prometheus listens on all interfaces inside the host-network namespace:

```sh
0.0.0.0:9000
```

Prometheus scrapes the local node metrics endpoint at:

```text
127.0.0.1:9090
```

The generated `coins-chain-node` testnet configs currently hardcode node
addresses, including metrics, to localhost. This is why `create.sh` uses
`--network host`: it lets Prometheus inside the container reach the host's
`127.0.0.1:9090`.

## Docker Host Networking Notes

On Linux, `--network host` makes the container share the host network namespace.
This is the simplest way for Prometheus in the container to scrape a node bound
to `127.0.0.1`.

On Docker Desktop for macOS, host networking requires Docker Desktop support and
must be enabled in Docker settings. If host networking is unavailable, this setup
may not be able to reach a node that only listens on `127.0.0.1`.

If you want to avoid host networking, the node metrics address should be changed
to listen on an address reachable from the container, and `create.sh` should use
explicit port publishing instead.

## Dashboard

`dashboard.json` contains panels for metrics that are common between the local
`coins-chain-node` metrics endpoint and the Alto dashboard metrics:

- `engine_finalized_blocks_freezer_resizes_total`
- `engine_marshal_processed_height`
- `network_tracker_directory_tracked`
- `runtime_inbound_bandwidth_total`
- `runtime_network_buffer_pool_buffer_pool_created`
- `runtime_outbound_bandwidth_total`
- `runtime_process_rss`
- `runtime_process_virtual_memory`
- `runtime_storage_buffer_pool_buffer_pool_created`
- `runtime_storage_buffer_pool_buffer_pool_exhausted_total_total`
- `runtime_tasks_running`

Counter-like metrics are shown as rates where useful.

## Troubleshooting

If Grafana starts without the dashboard, check that this directory is mounted at
`/workspace` in the container and that `/workspace/dashboard.json` exists.

If the Prometheus datasource is missing, check that Grafana was started with:

```sh
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
```

If the dashboard has no data, check that the node metrics endpoint is reachable:

```sh
curl http://localhost:9090/metrics
```

Also confirm Prometheus is running:

```text
http://localhost:9000/-/ready
```
