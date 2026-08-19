import type { Message } from "./types";
import { Wallet, type WalletHost, type WalletWasm } from "./wallet";

async function initWasm(): Promise<WalletWasm> {
  const wasm = await import("./wasm/nunchi_wallet_crypto");
  await wasm.default();
  wasm.init_panic_hook();
  return wasm;
}

let wasmPromise: Promise<WalletWasm> | null = null;

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
        height: 600,
      });
      return win?.id;
    },
    rpc: async (url, body) => {
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      return response.json();
    },
    wasm: () => {
      if (!wasmPromise) {
        wasmPromise = initWasm();
      }
      return wasmPromise;
    },
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
