import { randomRequestId } from "./ids";
import { isAllowedPageMessage } from "./page-messages";

window.addEventListener("message", async (event) => {
  if (event.source !== window) return;
  if (!event.data || typeof event.data.type !== "string") return;

  if (!isAllowedPageMessage(event.data.type)) {
    console.warn("[Nunchi Wallet] Blocked privileged message from page:", event.data.type);
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
        target: "nunchi-wallet-inpage",
        requestId,
        response,
      },
      "*"
    );
  } catch (error) {
    window.postMessage(
      {
        target: "nunchi-wallet-inpage",
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
script.onload = function () {
  (this as HTMLScriptElement).remove();
};
(document.head || document.documentElement).appendChild(script);
