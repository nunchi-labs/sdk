import type { Message } from "./types";
import { isAllowedPageOrigin } from "./origin";
import { Wallet, type WalletHost, type WalletWasm } from "./wallet";
// Static import: Vite wraps dynamic import() with a window-based preload helper
// that throws `window is not defined` in the MV3 service worker.
import initWasmModule, * as wasmBindings from "./wasm/nunchi_wallet_crypto";

async function initWasm(): Promise<WalletWasm> {
  const wasmUrl = new URL("./wasm/nunchi_wallet_crypto_bg.wasm", import.meta.url);
  await initWasmModule({ module_or_path: wasmUrl });
  wasmBindings.init_panic_hook();
  return wasmBindings;
}

let wasmPromise: Promise<WalletWasm> | null = null;
const pagePorts = new Map<string, Set<chrome.runtime.Port>>();

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "nunchi-page") {
    return;
  }
  const origin = port.sender?.origin || "";
  if (!isAllowedPageOrigin(origin)) {
    port.disconnect();
    return;
  }
  let ports = pagePorts.get(origin);
  if (!ports) {
    ports = new Set();
    pagePorts.set(origin, ports);
  }
  ports.add(port);
  port.onDisconnect.addListener(() => {
    const remaining = pagePorts.get(origin);
    remaining?.delete(port);
    if (remaining && remaining.size === 0) {
      pagePorts.delete(origin);
    }
  });
});

function broadcast(origin: string, event: string, params: unknown): void {
  for (const port of pagePorts.get(origin) ?? []) {
    try {
      port.postMessage({ event, params });
    } catch {
      pagePorts.get(origin)?.delete(port);
    }
  }
}

function chromeHost(): WalletHost {
  return {
    now: () => Date.now(),
    storageGet: (keys) => chrome.storage.local.get(keys),
    storageSet: (items) => chrome.storage.local.set(items),
    storageRemove: (keys) => chrome.storage.local.remove(keys),
    extensionId: chrome.runtime.id,
    openApproval: async (path) => {
      const win = await chrome.windows.create({
        url: chrome.runtime.getURL(path),
        type: "popup",
        width: 400,
        height: 640,
        focused: true,
      });
      return win?.id;
    },
    rpc: async (url, body) => {
      let response: Response;
      try {
        response = await fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });
      } catch (error) {
        throw new Error(`RPC request failed: ${error instanceof Error ? error.message : String(error)}`);
      }
      if (!response.ok) {
        throw new Error(`RPC HTTP ${response.status}`);
      }
      try {
        return await response.json();
      } catch {
        throw new Error("RPC returned non-JSON");
      }
    },
    wasm: () => {
      if (!wasmPromise) {
        wasmPromise = initWasm();
      }
      return wasmPromise;
    },
    broadcast,
  };
}

const wallet = new Wallet(chromeHost());

chrome.windows.onRemoved.addListener((windowId) => {
  wallet.rejectWindow(windowId);
});

chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  wallet
    .handleMessage(message, sender)
    .then((response) => sendResponse(response))
    .catch((error) => sendResponse({ success: false, error: error.message }));
  return true;
});
