# narae

`narae` is a local testnet runner with a ratatui dashboard. It currently runs process specs from
TOML, which fits the SDK as it exists today: the examples expose integration-test harnesses, not
standalone node binaries.

Run the current coins-chain harness:

```sh
cargo run -p narae -- coins-chain
```

Run configured commands:

```sh
cargo run -p narae -- run -c narae/examples/coins-chain.toml
```

## DRY Deployable Examples

The examples already know how to build a local network, but that code lives under `tests/common`.
The cleaner path is:

1. Extract the duplicated simulated-network builder into reusable crate code.
2. Put example-specific engine construction behind a small adapter trait.
3. Keep tests and `narae` consuming the same harness.
4. Add standalone node binaries only when the in-process harness is already shared.

That keeps test coverage and local deployment from drifting into two separate systems.
