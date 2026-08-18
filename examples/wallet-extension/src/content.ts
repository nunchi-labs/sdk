const script = document.createElement("script");
script.src = chrome.runtime.getURL("inpage.js");
script.type = "module";
(document.head || document.documentElement).appendChild(script);

window.addEventListener("message", async (event) => {
  if (event.source !== window) return;
  if (event.data.target !== "nunchi-wallet-content") return;

  const { type, payload, requestId } = event.data;

  try {
    const response = await chrome.runtime.sendMessage({ type, payload });

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
