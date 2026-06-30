FROM rust:1-bookworm AS builder

WORKDIR /workspace
COPY . .
RUN cargo build --release -p nunchi-coins-chain --bin coins-chain-node

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/coins-chain-node /usr/local/bin/coins-chain-node

ENTRYPOINT ["/usr/local/bin/coins-chain-node"]
