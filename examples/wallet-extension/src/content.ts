import { randomRequestId } from "./ids";
import { isTrustedPageRequest, PAGE_RESPONSE_TARGET } from "./page-messages";

const bridgeToken = randomRequestId("tok");

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
