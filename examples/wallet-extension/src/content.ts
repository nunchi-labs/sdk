import { randomRequestId } from "./ids";
import { isAllowedPageOrigin } from "./origin";
import { isTrustedPageRequest, PAGE_EVENT_TARGET, PAGE_RESPONSE_TARGET } from "./page-messages";

const bridgeToken = randomRequestId("tok");

function frameOrigin(): string {
  try {
    return window.location.origin || "";
  } catch {
    return "";
  }
}

function connectPagePort(): void {
  // Content scripts run in all_frames, including opaque/null and file: contexts.
  // The worker rejects those origins; skip connect entirely so we never spin a
  // connect/disconnect loop for as long as the page stays open.
  if (!isAllowedPageOrigin(frameOrigin())) {
    return;
  }

  const port = chrome.runtime.connect({ name: "nunchi-page" });
  port.onMessage.addListener((message: { event?: string; params?: unknown }) => {
    if (typeof message?.event !== "string") {
      return;
    }
    window.postMessage(
      {
        target: PAGE_EVENT_TARGET,
        token: bridgeToken,
        event: message.event,
        params: message.params,
      },
      "*"
    );
  });
  port.onDisconnect.addListener(() => {
    // Re-check: a frame can become opaque after navigation, and cold worker
    // restarts should still reconnect only for origins the worker will accept.
    if (!isAllowedPageOrigin(frameOrigin())) {
      return;
    }
    setTimeout(connectPagePort, 1000);
  });
}

connectPagePort();

window.addEventListener("message", async (event) => {
  if (event.source !== window) return;
  if (!isTrustedPageRequest(event.data || {}, bridgeToken)) {
    return;
  }

  const requestId = typeof event.data.requestId === "string" ? event.data.requestId : randomRequestId("req");

  try {
    const response = await chrome.runtime.sendMessage({
      type: event.data.type,
      payload: event.data.payload,
      requestId,
    });

    window.postMessage(
      {
        target: PAGE_RESPONSE_TARGET,
        token: bridgeToken,
        requestId,
        response,
      },
      "*"
    );
  } catch (error) {
    window.postMessage(
      {
        target: PAGE_RESPONSE_TARGET,
        token: bridgeToken,
        requestId,
        response: {
          success: false,
          error: error instanceof Error ? error.message : String(error),
        },
      },
      "*"
    );
  }
});

const script = document.createElement("script");
script.src = chrome.runtime.getURL("inpage.js");
script.dataset.nunchiBridge = bridgeToken;
script.onload = function () {
  (this as HTMLScriptElement).remove();
};
(document.head || document.documentElement).appendChild(script);
