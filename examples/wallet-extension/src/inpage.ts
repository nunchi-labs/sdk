import { randomRequestId } from "./ids";

const APPROVAL_TIMEOUT_MS = 5 * 60 * 1000;

interface NunchiProvider {
  isNunchi: boolean;
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on(event: string, handler: (...args: unknown[]) => void): void;
  removeListener(event: string, handler: (...args: unknown[]) => void): void;
}

interface CoinsProvider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

class EventEmitter {
  private listeners: Map<string, Set<(...args: unknown[]) => void>> = new Map();

  on(event: string, handler: (...args: unknown[]) => void): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(handler);
  }

  removeListener(event: string, handler: (...args: unknown[]) => void): void {
    this.listeners.get(event)?.delete(handler);
  }

  emit(event: string, ...args: unknown[]): void {
    this.listeners.get(event)?.forEach((handler) => handler(...args));
  }
}

class NunchiWalletProvider extends EventEmitter implements NunchiProvider {
  readonly isNunchi = true;
  private pendingRequests: Map<string, { resolve: (value: unknown) => void; reject: (error: Error) => void }> =
    new Map();
  private connectedAddress: string | null = null;

  constructor() {
    super();
    this.setupMessageListener();
  }

  private setupMessageListener(): void {
    window.addEventListener("message", (event) => {
      if (event.source !== window) return;
      if (event.data.target !== "nunchi-wallet-inpage") return;

      const { requestId, response } = event.data;
      const pending = this.pendingRequests.get(requestId);
      if (!pending) return;

      this.pendingRequests.delete(requestId);

      if (response.success) {
        pending.resolve(response.data);
      } else {
        pending.reject(new Error(response.error || "Request failed"));
      }
    });
  }

  private sendMessage(type: string, payload?: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const requestId = randomRequestId("req");
      this.pendingRequests.set(requestId, { resolve, reject });

      window.postMessage(
        {
          target: "nunchi-wallet-content",
          type,
          payload,
          requestId,
        },
        "*"
      );

      setTimeout(() => {
        if (this.pendingRequests.has(requestId)) {
          this.pendingRequests.delete(requestId);
          reject(new Error("Request timeout"));
        }
      }, APPROVAL_TIMEOUT_MS);
    });
  }

  async request(args: { method: string; params?: unknown[] }): Promise<unknown> {
    const { method, params = [] } = args;

    switch (method) {
      case "nunchi_requestAccounts": {
        const result = (await this.sendMessage("REQUEST_CONNECTION")) as { address?: string };
        if (!result?.address) {
          throw new Error("No account returned");
        }
        this.connectedAddress = result.address;
        this.emit("accountsChanged", [result.address]);
        return [result.address];
      }

      case "nunchi_accounts": {
        return this.connectedAddress ? [this.connectedAddress] : [];
      }

      case "nunchi_chainId": {
        const result = (await this.sendMessage("GET_CHAIN_ID")) as { chainId?: string };
        return result?.chainId || "nunchi-local";
      }

      case "nunchi_signTransaction": {
        const [txParams] = params as [{ coin: string; from: string; to: string; amount: string }];
        return this.sendMessage("REQUEST_SIGN", txParams);
      }

      case "nunchi_sendTransaction": {
        const [txParams] = params as [{ coin: string; from: string; to: string; amount: string }];
        return this.sendMessage("REQUEST_TRANSACTION", txParams);
      }

      default:
        throw new Error(`Method ${method} not supported`);
    }
  }
}

class CoinsProviderImpl implements CoinsProvider {
  constructor(private nunchi: NunchiWalletProvider) {}

  async request(args: { method: string; params?: unknown[] }): Promise<unknown> {
    return this.nunchi.request(args);
  }
}

const nunchiProvider = new NunchiWalletProvider();
const coinsProvider = new CoinsProviderImpl(nunchiProvider);

Object.defineProperty(window, "nunchi", {
  value: nunchiProvider,
  writable: false,
  configurable: false,
});

Object.defineProperty((window as unknown as { nunchi: NunchiProvider }).nunchi, "coins", {
  value: coinsProvider,
  writable: false,
  configurable: false,
});

window.dispatchEvent(new Event("nunchi#initialized"));
