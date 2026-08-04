use std::{path::Path, process::Command};

fn wallet_command(wallet_root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_nunchi-wallet"));
    command
        .arg("--wallet-root")
        .arg(wallet_root)
        .env_remove("NUNCHI_WALLET_PASSWORD");
    command
}

fn run_success(mut command: Command) -> String {
    let output = command.output().expect("run nunchi-wallet");
    if !output.status.success() {
        panic!(
            "command failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout).expect("stdout is utf-8")
}

fn run_failure(mut command: Command) -> String {
    let output = command.output().expect("run nunchi-wallet");
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded with stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8(output.stderr).expect("stderr is utf-8")
}

fn create_insecure_wallet(wallet_root: &Path, name: &str, chain_id: u64) -> serde_json::Value {
    let mut command = wallet_command(wallet_root);
    command
        .arg("create")
        .arg("--name")
        .arg(name)
        .arg("--chain-id")
        .arg(chain_id.to_string())
        .arg("--insecure-store");
    serde_json::from_str(&run_success(command)).expect("summary json")
}

#[test]
fn cli_create_list_show_and_address_use_wallet_root() {
    let temp = tempfile::tempdir().expect("tempdir");
    let summary = create_insecure_wallet(temp.path(), "default", 7);
    assert_eq!(summary["name"], "default");
    assert_eq!(summary["chain_id"], 7);
    let address = summary["address"].as_str().expect("address").to_string();
    assert!(address.starts_with("nch1"));

    let mut command = wallet_command(temp.path());
    command.arg("list");
    let listed: serde_json::Value = serde_json::from_str(&run_success(command)).expect("list json");
    assert_eq!(listed.as_array().expect("list array").len(), 1);
    assert_eq!(listed[0]["address"], address);

    let mut command = wallet_command(temp.path());
    command.arg("show").arg("--name").arg("default");
    let shown: serde_json::Value = serde_json::from_str(&run_success(command)).expect("show json");
    assert_eq!(shown["address"], address);

    let mut command = wallet_command(temp.path());
    command.arg("address").arg("--name").arg("default");
    assert_eq!(run_success(command).trim(), address);
}

#[test]
fn cli_submit_transfer_validates_inputs_before_rpc() {
    let temp = tempfile::tempdir().expect("tempdir");
    let summary = create_insecure_wallet(temp.path(), "default", 7);
    let address = summary["address"].as_str().expect("address");
    let coin = "22".repeat(32);

    let mut command = wallet_command(temp.path());
    command
        .arg("submit-transfer")
        .arg("--name")
        .arg("default")
        .arg("--rpc")
        .arg("http://127.0.0.1:1")
        .arg("--chain-id")
        .arg("8")
        .arg("--coin")
        .arg(&coin)
        .arg("--to")
        .arg(address)
        .arg("--amount")
        .arg("5");
    assert!(run_failure(command).contains("wallet chain_id 7 does not match --chain-id 8"));

    let mut command = wallet_command(temp.path());
    command
        .arg("submit-transfer")
        .arg("--name")
        .arg("default")
        .arg("--rpc")
        .arg("http://127.0.0.1:1")
        .arg("--chain-id")
        .arg("7")
        .arg("--coin")
        .arg(&coin)
        .arg("--to")
        .arg("not-an-address")
        .arg("--amount")
        .arg("5");
    assert!(run_failure(command).contains("invalid bech32 address"));

    let mut command = wallet_command(temp.path());
    command
        .arg("submit-transfer")
        .arg("--name")
        .arg("default")
        .arg("--rpc")
        .arg("http://127.0.0.1:1")
        .arg("--chain-id")
        .arg("7")
        .arg("--coin")
        .arg("not-hex")
        .arg("--to")
        .arg(address)
        .arg("--amount")
        .arg("5");
    assert!(run_failure(command).contains("invalid coin id"));

    let mut command = wallet_command(temp.path());
    command
        .arg("submit-transfer")
        .arg("--name")
        .arg("default")
        .arg("--rpc")
        .arg("http://127.0.0.1:1")
        .arg("--chain-id")
        .arg("7")
        .arg("--coin")
        .arg(&coin)
        .arg("--to")
        .arg(address)
        .arg("--amount")
        .arg("nan");
    assert!(run_failure(command).contains("amount must be a valid u128"));
}
