export interface WalletState {
  encrypted: string;
  salt: string;
  address: string;
  curve: string;
  needsBackup?: boolean;
}

export interface UnlockedWallet {
  privateKeyHex: string;
  publicKeyHex: string;
  address: string;
  curve: string;
}

export interface Settings {
  rpcUrl: string;
  network: string;
  chainId: string;
  displayCoin: string;
}

export interface ConnectionRequest {
  origin: string;
  timestamp: number;
}

export interface TransactionRequest {
  id: string;
  origin: string;
  nonce: number;
  coin: string;
  from: string;
  to: string;
  amount: string;
  timestamp: number;
  submit: boolean;
}

export interface Balance {
  coin: string;
  amount: string;
}

export interface SubmittedTx {
  hash: string;
  timestamp: number;
  /** The coin that left the wallet. */
  coin: string;
  to: string;
  amount: string;
  /** Absent means a plain transfer, so existing records keep working. */
  kind?: "send" | "swap";
  /** Swaps only: what came back. */
  toCoin?: string;
  toAmount?: string;
}

export type MessageType =
  | "UNLOCK_WALLET"
  | "LOCK_WALLET"
  | "GET_STATE"
  | "CREATE_WALLET"
  | "IMPORT_WALLET"
  | "REVEAL_BACKUP"
  | "CONFIRM_BACKUP"
  | "EXPORT_PRIVATE_KEY"
  | "DELETE_WALLET"
  | "REQUEST_CONNECTION"
  | "APPROVE_CONNECTION"
  | "REJECT_CONNECTION"
  | "GET_CONNECTED_SITES"
  | "DISCONNECT_SITE"
  | "REQUEST_TRANSACTION"
  | "REQUEST_SIGN"
  | "APPROVE_TRANSACTION"
  | "REJECT_TRANSACTION"
  | "SEND_TRANSACTION"
  | "CREATE_TOKEN"
  | "MINT"
  | "BURN"
  | "REGISTER_ACCOUNT_POLICY"
  | "GET_SETTINGS"
  | "UPDATE_SETTINGS"
  // Account management. Only the demo backend implements these today; the
  // real Wallet rejects them, and the popup hides the UI when it does.
  | "GET_ACCOUNTS"
  | "SWITCH_ACCOUNT"
  | "ADD_ACCOUNT"
  | "IMPORT_ACCOUNT"
  | "RENAME_ACCOUNT"
  | "GET_HOLDINGS"
  // Swap. No Nunchi chain endpoint backs these yet; the demo backend answers
  // them and the popup shows an unavailable state when nothing does.
  | "GET_SWAP_QUOTE"
  | "SWAP"
  | "GET_CHAIN_ID"
  | "GET_NONCE"
  | "GET_BALANCE"
  | "GET_ACTIVITY"
  | "GET_PENDING_REQUEST";

export interface Message<T = unknown> {
  type: MessageType;
  payload?: T;
  requestId?: string;
}

export interface Response<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  requestId?: string;
}
