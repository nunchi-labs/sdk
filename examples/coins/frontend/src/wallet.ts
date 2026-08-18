export interface NunchiProvider {
  isNunchi: boolean;
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  on(event: string, handler: (...args: unknown[]) => void): void;
  removeListener(event: string, handler: (...args: unknown[]) => void): void;
}

export function detectWallet(): NunchiProvider | null {
  if (typeof window === "undefined") return null;
  const provider = (window as { nunchi?: NunchiProvider }).nunchi;
  return provider?.isNunchi ? provider : null;
}

export async function connectWallet(provider: NunchiProvider): Promise<string[]> {
  const accounts = (await provider.request({
    method: "nunchi_requestAccounts",
  })) as string[];
  return accounts;
}

export async function sendTransaction(
  provider: NunchiProvider,
  params: { coin: string; from: string; to: string; amount: string }
): Promise<{ hash: string }> {
  const result = (await provider.request({
    method: "nunchi_sendTransaction",
    params: [params],
  })) as { hash: string };
  return result;
}
