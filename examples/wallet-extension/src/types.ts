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
  coin: string;
  to: string;
  amount: string;
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
