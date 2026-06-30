FROM rust:1-bookworm AS builder

WORKDIR /workspace
COPY . .
RUN cargo build --release \
    -p nunchi-coins-chain --bin coins-chain-node \
    -p nunchi-coins-indexer --bin coins-chain-indexer \
    -p xtask --bin xtask

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 nunchi \
    && useradd --uid 10001 --gid nunchi --shell /bin/false --create-home nunchi \
    && mkdir -p /var/lib/nunchi/coins-chain \
    && chown -R nunchi:nunchi /var/lib/nunchi

COPY --from=builder /workspace/target/release/coins-chain-node /usr/local/bin/coins-chain-node

USER nunchi
WORKDIR /var/lib/nunchi/coins-chain
VOLUME ["/var/lib/nunchi/coins-chain"]
EXPOSE 30000 8545 9090

ENTRYPOINT ["/usr/local/bin/coins-chain-node"]

FROM debian:bookworm-slim AS indexer

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 10001 nunchi \
    && useradd --uid 10001 --gid nunchi --shell /bin/false --create-home nunchi

COPY --from=builder /workspace/target/release/coins-chain-indexer /usr/local/bin/coins-chain-indexer

USER nunchi
EXPOSE 8080
VOLUME ["/usr/share/nunchi/coins/frontend"]

ENTRYPOINT ["/usr/local/bin/coins-chain-indexer"]

FROM debian:bookworm-slim AS tools

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/xtask /usr/local/bin/xtask

WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/xtask"]
