check:
    @echo "Checking for unused dependencies..."
    cargo +nightly udeps --all-features --all-targets
    @echo "Checking for clippy warnings..."
    cargo clippy --all --all-targets -- -D warnings

test:
    @echo "Running tests..."
    @cargo nextest run --workspace

coverage:
    @echo "Running tests with coverage..."
    @cargo llvm-cov nextest --workspace

stability-check:
    @echo "Running Commonware stability check (>= BETA) for noble-node..."
    RUSTFLAGS="--cfg commonware_stability_BETA" cargo +nightly build -p noble-node

install-deps:
    #!/usr/bin/env bash
    set -euo pipefail

    echo "Installing project dependencies..."

    if [[ "$(uname)" == "Linux" ]] && ! command -v mold > /dev/null; then
        echo "Installing mold linker..."
        sudo apt-get update && sudo apt-get install -y mold
    fi

    for tool in cargo-udeps cargo-llvm-cov cargo-nextest; do \
        if ! command -v $tool > /dev/null; then \
        echo "Installing $tool..."; \
        cargo install $tool; \
        else \
        echo "$tool is already installed."; \
        fi; \
    done
