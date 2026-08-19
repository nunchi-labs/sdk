const ALLOWED_PAGE_MESSAGES = new Set([
  "REQUEST_CONNECTION",
  "REQUEST_TRANSACTION",
]);

window.addEventListener("message", async (event) => {
  if (event.source !== window) return;
  if (!event.data || typeof event.data.type !== "string") return;

  if (!ALLOWED_PAGE_MESSAGES.has(event.data.type)) {
    console.warn("[Nunchi Wallet] Blocked privileged message from page:", event.data.type);
    return;
  }

  const requestId = event.data.requestId || `req-${Date.now()}-${Math.random()}`;

  try {
    const response = await chrome.runtime.sendMessage({
      type: event.data.type,
      payload: event.data.payload,
      requestId,
      origin: window.location.origin,
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
script.type = "module";
script.onload = function () {
  (this as HTMLScriptElement).remove();
};
(document.head || document.documentElement).appendChild(script);
