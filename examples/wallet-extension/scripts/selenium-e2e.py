#!/usr/bin/env python3
"""Load the built MV3 wallet in Chromium and exercise the popup through Selenium."""

from __future__ import annotations
 
import argparse
import http.server
import json
import os
import shutil
import socketserver
import sys
import tempfile
import threading
import time
from pathlib import Path

ARTIFACT_DIR = Path("/tmp/nunchi-wallet-selenium-last")

from selenium import webdriver
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import Select, WebDriverWait

PASSWORD = "correct-password"
SHORT_PASSWORD = "short"
DISPLAY_COIN = "00" * 32
DAPP_HTML = """<!doctype html>
<html>
  <body>
    <h1>Nunchi dApp fixture</h1>
    <pre id="status">waiting</pre>
    <script>
      window.addEventListener("nunchi#initialized", () => {
        document.getElementById("status").textContent = "ready";
      });
      setTimeout(() => {
        if (window.nunchi && window.nunchi.isNunchi) {
          document.getElementById("status").textContent = "ready";
        }
      }, 500);
    </script>
  </body>
</html>
"""


class Failures(list):
    def check(self, name: str, ok: bool, detail: str = "") -> None:
        status = "PASS" if ok else "FAIL"
        suffix = f" ({detail})" if detail else ""
        print(f"[{status}] {name}{suffix}")
        if not ok:
            self.append(name)


class RpcState:
    def __init__(self) -> None:
        self.nonce = 0
        self.submitted: list[str] = []
        self.lock = threading.Lock()


def testid(name: str) -> tuple[str, str]:
    return (By.CSS_SELECTOR, f'[data-testid="{name}"]')


def wait_el(driver, name: str, timeout: int = 15):
    return WebDriverWait(driver, timeout).until(EC.presence_of_element_located(testid(name)))


def wait_click(driver, name: str, timeout: int = 15):
    button = WebDriverWait(driver, timeout).until(EC.element_to_be_clickable(testid(name)))
    button.click()
    return button


def fill(driver, name: str, value: str, timeout: int = 15) -> None:
    field = wait_el(driver, name, timeout)
    field.click()
    field.send_keys(Keys.CONTROL, "a")
    field.send_keys(Keys.BACKSPACE)
    field.send_keys(value)


def error_text(driver, timeout: int = 8) -> str:
    return wait_el(driver, "error", timeout).text.strip()


def wait_text(driver, text: str, timeout: int = 15):
    WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((By.XPATH, f"//*[contains(normalize-space(.), {text!r})]"))
    )


def wait_create_result(driver, timeout: int = 45) -> str:
    def settled(d):
        if d.find_elements(*testid("backup-key")) or d.find_elements(*testid("reveal-key")):
            return "backup"
        errors = [el.text.strip() for el in d.find_elements(*testid("error")) if el.text.strip()]
        creating = d.find_elements(By.XPATH, "//button[contains(., 'Creating')]")
        if errors and not creating:
            return errors[0]
        return False

    return WebDriverWait(driver, timeout).until(settled)


def open_popup(driver, ext_id: str):
    driver.set_window_size(420, 760)
    driver.get(f"chrome-extension://{ext_id}/popup.html")
    WebDriverWait(driver, 20).until(lambda d: d.find_element(By.ID, "root"))


def find_extension_id(driver, timeout: int = 20) -> str:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        targets = driver.execute_cdp_cmd("Target.getTargets", {})
        for info in targets.get("targetInfos", []):
            url = info.get("url") or ""
            if url.startswith("chrome-extension://"):
                ext_id = url.split("/")[2]
                if ext_id:
                    return ext_id
        last = str(targets)
        time.sleep(0.4)
    raise TimeoutException(f"extension service worker not found: {last[:400]}")


def start_driver(ext_dir: Path, profile: Path) -> webdriver.Chrome:
    options = Options()
    options.binary_location = "/usr/bin/chromium"
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--disable-notifications")
    options.add_argument("--disable-popup-blocking")
    options.add_argument("--disable-background-networking")
    options.add_argument("--disable-features=DisableLoadExtensionCommandLineSwitch")
    options.add_argument(f"--user-data-dir={profile}")
    options.add_argument(f"--load-extension={ext_dir}")
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    service = Service()
    driver = webdriver.Chrome(options=options, service=service)
    driver.set_page_load_timeout(30)
    return driver


def home_address(driver) -> str:
    el = wait_el(driver, "home-address")
    return el.get_attribute("data-address") or el.text


def create_wallet_and_backup(driver, failures: Failures) -> tuple[str, str]:
    wait_el(driver, "create-wallet")
    failures.check("onboarding shows create and import", bool(driver.find_elements(*testid("import-wallet"))))
    disclosure = wait_el(driver, "security-disclosure").text
    failures.check(
        "onboarding discloses local keys and unaudited status",
        "cannot recover" in disclosure.lower() and "unaudited" in disclosure.lower(),
        disclosure[:80],
    )

    wait_click(driver, "create-wallet")
    wait_el(driver, "create-submit")
    Select(wait_el(driver, "curve-select")).select_by_value("Ed25519")

    fill(driver, "password", PASSWORD)
    fill(driver, "confirm-password", SHORT_PASSWORD)
    wait_click(driver, "create-submit")
    failures.check("create rejects mismatched passwords", "Passwords do not match" in error_text(driver))

    fill(driver, "password", SHORT_PASSWORD)
    fill(driver, "confirm-password", SHORT_PASSWORD)
    wait_click(driver, "create-submit")
    failures.check("create rejects short password", "Password must be at least 8 characters" in error_text(driver))

    fill(driver, "password", PASSWORD)
    fill(driver, "confirm-password", PASSWORD)
    wait_click(driver, "create-submit")
    outcome = wait_create_result(driver, timeout=45)
    if outcome != "backup":
        raise AssertionError(f"create did not reach backup screen: {outcome}")
    wait_text(driver, "Save Your Key", timeout=10)
    failures.check("create reaches backup screen", True)

    if driver.find_elements(*testid("reveal-key")):
        fill(driver, "backup-password", PASSWORD)
        wait_click(driver, "reveal-key")

    key_box = wait_el(driver, "backup-key", timeout=20)
    private_key = key_box.get_attribute("value") or ""
    failures.check("backup reveals hex private key", len(private_key) >= 64, private_key[:12])

    continue_btn = wait_el(driver, "backup-continue")
    failures.check("continue disabled until key is saved", not continue_btn.is_enabled())
    wait_el(driver, "backup-saved").click()
    failures.check("continue enabled after checkbox", continue_btn.is_enabled())
    wait_click(driver, "backup-continue")
    wait_el(driver, "send")
    address = home_address(driver)
    failures.check("home shows nch address", address.startswith("nch1"), address)
    return address, private_key


def exercise_send_validation(driver, address: str, failures: Failures) -> None:
    wait_click(driver, "send")
    wait_el(driver, "recipient")
    wait_click(driver, "send-submit")
    failures.check("send requires all fields", "All fields are required" in error_text(driver))

    fill(driver, "recipient", "not-an-address")
    fill(driver, "coin", DISPLAY_COIN)
    fill(driver, "amount", "1")
    wait_click(driver, "send-submit")
    failures.check("send rejects invalid address", "Invalid nch address" in error_text(driver))

    fill(driver, "recipient", address)
    fill(driver, "amount", "1.5")
    wait_click(driver, "send-submit")
    failures.check("send rejects decimal amount", "Amount must be a whole number" in error_text(driver))

    fill(driver, "amount", "1")
    wait_click(driver, "send-submit")
    wait_el(driver, "send-review")
    failures.check("send review shows recipient", address in wait_el(driver, "review-to").text)
    wait_click(driver, "send-edit")
    wait_el(driver, "recipient")
    wait_click(driver, "back")
    wait_el(driver, "send")


def exercise_settings_and_transfer(driver, address: str, rpc_url: str, failures: Failures) -> None:
    wait_click(driver, "activity")
    wait_el(driver, "activity-empty")
    failures.check("empty activity list", True)
    wait_click(driver, "back")
    wait_el(driver, "send")

    wait_click(driver, "settings")
    wait_el(driver, "settings-rpc")
    failures.check("default rpc is localhost", "localhost" in (wait_el(driver, "settings-rpc").get_attribute("value") or ""))

    fill(driver, "settings-rpc", "ftp://example.com")
    wait_click(driver, "settings-save")
    failures.check("settings reject non-http rpc", "http or https" in error_text(driver).lower() or "invalid" in error_text(driver).lower())

    fill(driver, "settings-rpc", rpc_url)
    fill(driver, "settings-display-coin", DISPLAY_COIN)
    wait_click(driver, "settings-save")
    wait_el(driver, "send", timeout=20)
    failures.check("home shows display-coin balance", wait_el(driver, "balance-value", timeout=20).text.strip() == "1250")

    wait_click(driver, "send")
    fill(driver, "recipient", address)
    if not (wait_el(driver, "coin").get_attribute("value") or "").strip():
        fill(driver, "coin", DISPLAY_COIN)
    fill(driver, "amount", "1")
    wait_click(driver, "send-submit")
    wait_el(driver, "send-review")
    wait_click(driver, "send-submit")
    wait_el(driver, "send-success", timeout=30)
    failures.check("popup send submits through mock rpc", True)
    WebDriverWait(driver, 10).until(lambda d: d.find_elements(*testid("send")))
    wait_click(driver, "activity")
    wait_el(driver, "activity-item", timeout=10)
    failures.check("activity lists submitted transfer", True)
    wait_click(driver, "back")
    wait_el(driver, "send")


def exercise_export_and_lock(driver, private_key: str, failures: Failures) -> None:
    wait_click(driver, "settings")
    fill(driver, "export-password", "wrong-password")
    wait_click(driver, "export-key")
    failures.check("export rejects wrong password", "Invalid password" in error_text(driver))
    fill(driver, "export-password", PASSWORD)
    wait_click(driver, "export-key")
    exported = wait_el(driver, "exported-key", timeout=20).get_attribute("value") or ""
    failures.check("export returns the backup key", exported == private_key, exported[:12])
    wait_click(driver, "back")
    wait_el(driver, "send")

    wait_click(driver, "lock")
    wait_el(driver, "unlock-submit")
    fill(driver, "password", "wrong-password")
    wait_click(driver, "unlock-submit")
    failures.check("unlock rejects wrong password", "Invalid password" in error_text(driver))
    fill(driver, "password", PASSWORD)
    wait_click(driver, "unlock-submit")
    wait_el(driver, "send", timeout=20)
    failures.check("unlock with correct password returns home", True)


def open_dapp(driver, dapp_url: str) -> None:
    driver.get(dapp_url)
    WebDriverWait(driver, 15).until(
        lambda d: d.execute_script("return !!(window.nunchi && window.nunchi.isNunchi && window.nunchi.coins)")
    )


def nunchi_async(driver, script: str, *args):
    return driver.execute_async_script(script, *args)


def check_inpage_provider(driver, dapp_url: str, failures: Failures) -> None:
    open_dapp(driver, dapp_url)
    chain_id = nunchi_async(
        driver,
        """
        const done = arguments[0];
        window.nunchi.request({ method: "nunchi_chainId" })
          .then(done)
          .catch((err) => done("error:" + err.message));
        """,
    )
    failures.check("inpage provider reports chain id", chain_id == "nunchi-local", str(chain_id))

    accounts = nunchi_async(
        driver,
        """
        const done = arguments[0];
        window.nunchi.request({ method: "nunchi_accounts" })
          .then(done)
          .catch((err) => done("error:" + err.message));
        """,
    )
    failures.check("inpage accounts empty before connect", accounts == [], str(accounts))

    frozen = driver.execute_script(
        """
        const desc = Object.getOwnPropertyDescriptor(window, "nunchi");
        return !!(desc && desc.writable === false && desc.configurable === false);
        """
    )
    failures.check("window.nunchi is non-writable", frozen is True, str(frozen))
    page_chrome = driver.execute_script("return typeof chrome !== 'undefined' && !!(chrome && chrome.runtime && chrome.runtime.sendMessage)")
    failures.check("page cannot send extension runtime messages", page_chrome is False, str(page_chrome))

    unknown = nunchi_async(
        driver,
        """
        const done = arguments[0];
        window.nunchi.request({ method: "nunchi_signMessage" })
          .then((value) => done("ok:" + JSON.stringify(value)))
          .catch((err) => done(err.message));
        """,
    )
    failures.check("unknown provider method is rejected", "not supported" in str(unknown), str(unknown))


def snapshot_targets(driver, fragment: str) -> set[str]:
    known: set[str] = set()
    targets = driver.execute_cdp_cmd("Target.getTargets", {})
    for info in targets.get("targetInfos", []):
        url = info.get("url") or ""
        tid = info.get("targetId") or ""
        if fragment in url:
            if tid:
                known.add(tid)
            if url:
                known.add(url)
    return known


def wait_cdp_url(driver, fragment: str, known: set[str] | None = None, timeout: int = 15) -> tuple[str, str]:
    seen = known or set()
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        targets = driver.execute_cdp_cmd("Target.getTargets", {})
        last = str(targets)
        for info in targets.get("targetInfos", []):
            url = info.get("url") or ""
            tid = info.get("targetId") or ""
            if fragment in url and tid not in seen and url not in seen:
                return url, tid
        time.sleep(0.3)
    raise TimeoutException(f"CDP target containing {fragment!r} not found: {last[:400]}")


def decide_approval(driver, dapp_handle: str, fragment: str, button: str, known: set[str] | None = None) -> None:
    approval_url, _popup_target = wait_cdp_url(driver, fragment, known)
    driver.switch_to.new_window("tab")
    driver.get(approval_url)
    wait_click(driver, button, timeout=15)
    driver.switch_to.window(dapp_handle)


def cleanup_extra_windows(driver, dapp_handle: str) -> None:
    for handle in list(driver.window_handles):
        if handle != dapp_handle:
            try:
                driver.switch_to.window(handle)
                driver.close()
            except Exception:
                pass
    driver.switch_to.window(dapp_handle)


def start_provider_request(driver, method: str, params=None) -> None:
    driver.execute_script(
        """
        const method = arguments[0];
        const params = arguments[1] || [];
        window.__nunchiResult = null;
        window.nunchi.request({ method, params })
          .then((value) => { window.__nunchiResult = { ok: value }; })
          .catch((err) => { window.__nunchiResult = { error: err.message }; });
        """,
        method,
        params or [],
    )


def wait_provider_result(driver, timeout: int = 20):
    return WebDriverWait(driver, timeout).until(lambda d: d.execute_script("return window.__nunchiResult"))


def check_locked_connect(driver, ext_id: str, dapp_url: str, failures: Failures) -> None:
    open_popup(driver, ext_id)
    wait_click(driver, "lock")
    wait_el(driver, "unlock-submit")
    open_dapp(driver, dapp_url)
    locked = nunchi_async(
        driver,
        """
        const done = arguments[0];
        window.nunchi.request({ method: "nunchi_requestAccounts" })
          .then((value) => done({ ok: value }))
          .catch((err) => done({ error: err.message }));
        """,
    )
    failures.check(
        "locked wallet rejects dapp connect",
        isinstance(locked, dict) and "locked" in str(locked.get("error", "")).lower(),
        str(locked),
    )
    open_popup(driver, ext_id)
    fill(driver, "password", PASSWORD)
    wait_click(driver, "unlock-submit")
    wait_el(driver, "send", timeout=20)


def check_connection_and_transactions(
    driver, ext_id: str, dapp_url: str, address: str, failures: Failures
) -> None:
    open_dapp(driver, dapp_url)
    dapp_handle = driver.current_window_handle

    known = snapshot_targets(driver, "approve=connection")
    start_provider_request(driver, "nunchi_requestAccounts")
    decide_approval(driver, dapp_handle, "approve=connection", "reject-connect", known)
    rejected = wait_provider_result(driver)
    cleanup_extra_windows(driver, dapp_handle)
    failures.check(
        "dapp connect reject returns user rejected",
        isinstance(rejected, dict) and "rejected" in str(rejected.get("error", "")).lower(),
        str(rejected),
    )

    known = snapshot_targets(driver, "approve=connection")
    start_provider_request(driver, "nunchi_requestAccounts")
    decide_approval(driver, dapp_handle, "approve=connection", "approve-connect", known)
    approved = wait_provider_result(driver)
    cleanup_extra_windows(driver, dapp_handle)
    ok = isinstance(approved, dict) and isinstance(approved.get("ok"), list) and approved["ok"] == [address]
    failures.check("dapp receives connected account", ok, str(approved))

    accounts = nunchi_async(
        driver,
        """
        const done = arguments[0];
        window.nunchi.request({ method: "nunchi_accounts" }).then(done).catch((err) => done("error:" + err.message));
        """,
    )
    failures.check("nunchi_accounts returns connected address", accounts == [address], str(accounts))

    open_dapp(driver, dapp_url)
    accounts_after_reload = nunchi_async(
        driver,
        """
        const done = arguments[0];
        window.nunchi.request({ method: "nunchi_accounts" }).then(done).catch((err) => done("error:" + err.message));
        """,
    )
    failures.check(
        "nunchi_accounts survives page reload",
        accounts_after_reload == [address],
        str(accounts_after_reload),
    )

    dapp_handle = driver.current_window_handle
    tx = {"coin": DISPLAY_COIN, "from": address, "to": address, "amount": "2"}
    known = snapshot_targets(driver, "approve=transaction")
    start_provider_request(driver, "nunchi_sendTransaction", [tx])
    decide_approval(driver, dapp_handle, "approve=transaction", "reject-tx", known)
    tx_rejected = wait_provider_result(driver)
    cleanup_extra_windows(driver, dapp_handle)
    failures.check(
        "dapp send reject returns user rejected",
        isinstance(tx_rejected, dict) and "rejected" in str(tx_rejected.get("error", "")).lower(),
        str(tx_rejected),
    )

    known = snapshot_targets(driver, "approve=transaction")
    start_provider_request(driver, "nunchi_sendTransaction", [tx])
    decide_approval(driver, dapp_handle, "approve=transaction", "approve-tx", known)
    tx_approved = wait_provider_result(driver, timeout=30)
    cleanup_extra_windows(driver, dapp_handle)
    hash_ok = isinstance(tx_approved, dict) and isinstance(tx_approved.get("ok"), dict) and "hash" in tx_approved["ok"]
    failures.check("dapp send confirms through mock rpc", hash_ok, str(tx_approved))

    disconnected = nunchi_async(
        driver,
        """
        const done = arguments[0];
        window.nunchi.request({ method: "nunchi_disconnect" })
          .then((value) => done({ ok: value }))
          .catch((err) => done({ error: err.message }));
        """,
    )
    failures.check("nunchi_disconnect succeeds", isinstance(disconnected, dict) and disconnected.get("ok") is True, str(disconnected))
    accounts_after = nunchi_async(
        driver,
        """
        const done = arguments[0];
        window.nunchi.request({ method: "nunchi_accounts" }).then(done).catch((err) => done("error:" + err.message));
        """,
    )
    failures.check("accounts empty after disconnect", accounts_after == [], str(accounts_after))

    open_popup(driver, ext_id)
    wait_click(driver, "settings")
    wait_el(driver, "connected-empty", timeout=10)
    failures.check("settings shows no connected sites after disconnect", True)
    wait_click(driver, "back")
    wait_el(driver, "send")


def delete_and_import(driver, private_key: str, expected_address: str, failures: Failures) -> None:
    wait_click(driver, "settings")
    fill(driver, "delete-password", PASSWORD)
    fill(driver, "delete-confirm", "delete")
    wait_click(driver, "delete-wallet")
    failures.check("delete requires DELETE confirmation", "Type DELETE to confirm" in error_text(driver))
    fill(driver, "delete-confirm", "DELETE")
    wait_click(driver, "delete-wallet")
    wait_el(driver, "create-wallet", timeout=20)
    failures.check("delete returns to onboarding", True)

    wait_click(driver, "import-wallet")
    wait_click(driver, "import-submit")
    import_empty = error_text(driver)
    failures.check("import requires a private key", "Private key is required" in import_empty, import_empty)

    fill(driver, "import-key", private_key)
    fill(driver, "password", SHORT_PASSWORD)
    fill(driver, "confirm-password", SHORT_PASSWORD)
    wait_click(driver, "import-submit")
    failures.check("import rejects short password", "Password must be at least 8 characters" in error_text(driver))

    fill(driver, "password", PASSWORD)
    fill(driver, "confirm-password", SHORT_PASSWORD)
    wait_click(driver, "import-submit")
    failures.check("import rejects mismatched passwords", "Passwords do not match" in error_text(driver))

    fill(driver, "import-key", "not-hex")
    fill(driver, "password", PASSWORD)
    fill(driver, "confirm-password", PASSWORD)
    wait_click(driver, "import-submit")
    failures.check("import rejects invalid hex", "hex" in error_text(driver).lower(), error_text(driver))

    fill(driver, "import-key", private_key)
    wait_click(driver, "import-submit")
    wait_el(driver, "send", timeout=30)
    address = home_address(driver)
    failures.check("import skips backup and restores address", address == expected_address, address)


def serve_fixture(html: str) -> tuple[int, RpcState, callable]:
    state = RpcState()
    directory_ready = {"html": html}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return

        def do_GET(self):
            body = directory_ready["html"].encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b"{}"
            try:
                request = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                request = {}
            method = request.get("method")
            req_id = request.get("id")
            with state.lock:
                if method == "coins.nonce":
                    result = {"nonce": state.nonce}
                elif method == "coins.balance":
                    result = {"amount": "1250"}
                elif method == "coins.submit_transaction":
                    tx = ""
                    params = request.get("params") or {}
                    if isinstance(params, dict):
                        tx = str(params.get("transaction") or "")
                    state.submitted.append(tx)
                    state.nonce += 1
                    result = {"hash": "0x" + "ab" * 32}
                else:
                    payload = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"message": f"unknown method {method}"},
                    }
                    self._json(payload)
                    return
            self._json({"jsonrpc": "2.0", "id": req_id, "result": result})

        def _json(self, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    class ReusableServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    httpd = None
    last_error = None
    for port in (8545, 0):
        try:
            httpd = ReusableServer(("127.0.0.1", port), Handler)
            break
        except OSError as exc:
            last_error = exc
    if httpd is None:
        raise RuntimeError(f"failed to bind fixture server: {last_error}")
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd.server_address[1], state, httpd.shutdown


def run(ext_dir: Path) -> int:
    failures = Failures()
    work = Path(tempfile.mkdtemp(prefix="nunchi-wallet-selenium-"))
    port, _state, stop_server = serve_fixture(DAPP_HTML)
    dapp_url = f"http://127.0.0.1:{port}/"
    rpc_url = f"http://127.0.0.1:{port}/"
    profile = work / "profile"
    driver = None

    try:
        driver = start_driver(ext_dir, profile)
        ext_id = find_extension_id(driver)
        print(f"extension id {ext_id}")
        print(f"fixture server {dapp_url}")
        open_popup(driver, ext_id)
        address, private_key = create_wallet_and_backup(driver, failures)
        exercise_send_validation(driver, address, failures)
        exercise_settings_and_transfer(driver, address, rpc_url, failures)
        exercise_export_and_lock(driver, private_key, failures)
        check_locked_connect(driver, ext_id, dapp_url, failures)
        check_inpage_provider(driver, dapp_url, failures)
        check_connection_and_transactions(driver, ext_id, dapp_url, address, failures)
        delete_and_import(driver, private_key, address, failures)
    except Exception as exc:
        failures.check("selenium run completed without exception", False, str(exc))
        if driver is not None:
            try:
                ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
                shot = ARTIFACT_DIR / "failure.png"
                html = ARTIFACT_DIR / "failure.html"
                driver.save_screenshot(str(shot))
                html.write_text(driver.page_source, encoding="utf-8")
                print(f"wrote {shot}")
                print(f"wrote {html}")
            except Exception:
                pass
        raise
    finally:
        if driver is not None:
            driver.quit()
        stop_server()
        shutil.rmtree(work, ignore_errors=True)

    print(f"{len(failures)} failed")
    return 1 if failures else 0


def main() -> int:
    if not os.environ.get("DISPLAY") and shutil.which("xvfb-run") and not os.environ.get("NUNCHI_SELENIUM_NESTED"):
        os.environ["NUNCHI_SELENIUM_NESTED"] = "1"
        os.execvp(
            "xvfb-run",
            [
                "xvfb-run",
                "-a",
                "--server-args=-screen 0 1280x800x24",
                sys.executable,
                *sys.argv,
            ],
        )

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--extension",
        default=str(Path(__file__).resolve().parents[1] / "dist"),
        help="unpacked MV3 extension directory",
    )
    args = parser.parse_args()
    ext_dir = Path(args.extension).resolve()
    if not (ext_dir / "manifest.json").exists():
        print(f"missing manifest in {ext_dir}; run npm run build", file=sys.stderr)
        return 2
    return run(ext_dir)


if __name__ == "__main__":
    sys.exit(main())
