check:
    @echo "Checking for unused dependencies..."
    cargo +nightly udeps --locked --all-features --all-targets
    @echo "Checking for clippy warnings..."
    cargo clippy --locked --all --all-features --all-targets -- -D warnings

test:
    @echo "Running tests..."
    @cargo nextest run --locked --workspace --all-features --all-targets
    @echo "Running doctests..."
    @cargo test --locked --workspace --all-features --doc
    @echo "Running wallet wasm-crypto tests..."
    @cargo test --locked --manifest-path examples/wallet-extension/wasm-crypto/Cargo.toml

mcp-build:
    #!/usr/bin/env bash
    set -euo pipefail
    cd mcp
    npm ci
    npm run build

mcp:
    #!/usr/bin/env bash
    set -euo pipefail
    cd mcp
    if [[ ! -d node_modules ]]; then
        npm ci
    fi
    npx wrangler d1 migrations apply nunchi-mcp-search --local
    echo "Server will listen on http://127.0.0.1:8787."
    echo "In another terminal, index this checkout: just mcp-index"
    npm run dev

mcp-index:
    #!/usr/bin/env bash
    set -euo pipefail
    cd mcp
    if [[ ! -d node_modules ]]; then
        npm ci
    fi
    node --experimental-strip-types scripts/index-repo.mjs

wallet-test:
    @echo "Running wallet extension tests..."
    cd examples/wallet-extension && npm test

wallet-live:
    @echo "Running wallet live-chain tests..."
    ./examples/wallet-extension/scripts/run-live-tests.sh

coverage:
    @echo "Running tests with coverage..."
    @cargo llvm-cov --locked --all-features nextest --workspace --all-targets

stability-check:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Checking the workspace builds with Commonware stability ALPHA..."
    flags=(--cfg commonware_stability_ALPHA)
    if [[ "$(uname)" == "Linux" ]] && command -v mold >/dev/null; then
        flags+=(-C link-arg=-fuse-ld=mold)
    fi
    RUSTFLAGS="${flags[*]}" cargo build --workspace --locked --all-targets

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
