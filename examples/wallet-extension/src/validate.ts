import { bech32 } from "bech32";

export const ADDRESS_HRP = "nch";
export const COIN_HEX_LENGTH = 64;
export const PRIVATE_KEY_HEX_LENGTHS = new Set([64, 66]);
export const U128_MAX = (1n << 128n) - 1n;
export const MIN_PASSWORD_LENGTH = 8;
export const MAX_SYMBOL_BYTES = 32;
export const MAX_NAME_BYTES = 128;
export const MAX_LABEL_BYTES = 64;
export const MAX_SIGNER_KEYS = 16;

export function normalizeHex(value: string): string {
  let hex = value.trim().toLowerCase();
  if (hex.startsWith("0x")) {
    hex = hex.slice(2);
  }
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have even length");
  }
  if (!/^[0-9a-f]*$/.test(hex)) {
    throw new Error("Hex string contains invalid characters");
  }
  return hex;
}

export function requireCoinHex(value: string): string {
  const hex = normalizeHex(value);
  if (hex.length !== COIN_HEX_LENGTH) {
    throw new Error("Coin id must be 32 bytes hex");
  }
  return hex;
}

export function requireAmount(value: string): string {
  const amount = value.trim();
  if (!/^(0|[1-9][0-9]*)$/.test(amount)) {
    throw new Error("Amount must be a whole number");
  }
  if (BigInt(amount) > U128_MAX) {
    throw new Error("Amount exceeds u128");
  }
  return amount;
}

export function requireAddress(value: string): string {
  const address = value.trim();
  try {
    const decoded = bech32.decode(address);
    if (decoded.prefix !== ADDRESS_HRP) {
      throw new Error("wrong hrp");
    }
    if (bech32.fromWords(decoded.words).length !== 32) {
      throw new Error("wrong length");
    }
  } catch {
    throw new Error("Invalid nch address");
  }
  return address;
}

export function requirePrivateKeyHex(value: string): string {
  const hex = normalizeHex(value);
  if (!PRIVATE_KEY_HEX_LENGTHS.has(hex.length)) {
    throw new Error("Private key hex must be 32 or 33 bytes");
  }
  return hex;
}

export function requireCurve(value: string): "Ed25519" | "Secp256r1" {
  if (value !== "Ed25519" && value !== "Secp256r1") {
    throw new Error("Unsupported curve");
  }
  return value;
}

export function requirePassword(password: unknown): string {
  if (typeof password !== "string") {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  if (password !== password.trim() || /[\x00-\x1f\x7f]/.test(password)) {
    throw new Error("Password contains invalid characters");
  }
  return password;
}

export function requireLabel(value: string, field: string): string {
  const label = value.trim();
  if (!label) {
    throw new Error(`${field} is required`);
  }
  if (label.length > MAX_LABEL_BYTES) {
    throw new Error(`${field} is too long`);
  }
  if (/[\x00-\x1f\x7f]/.test(label)) {
    throw new Error(`${field} contains invalid characters`);
  }
  return label;
}

export function requireTokenSymbol(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("Token symbol is required");
  }
  const symbol = value.trim();
  if (!symbol) {
    throw new Error("Token symbol is required");
  }
  if (symbol.length > MAX_SYMBOL_BYTES) {
    throw new Error("Token symbol is too long");
  }
  if (!/^[A-Za-z0-9]+$/.test(symbol)) {
    throw new Error("Token symbol contains invalid characters");
  }
  return symbol;
}

export function requireTokenName(value: unknown): string {
  if (typeof value !== "string") {
    throw new Error("Token name is required");
  }
  const name = value.trim();
  if (!name) {
    throw new Error("Token name is required");
  }
  if (name.length > MAX_NAME_BYTES) {
    throw new Error("Token name is too long");
  }
  if (/[\x00-\x1f\x7f]/.test(name)) {
    throw new Error("Token name contains invalid characters");
  }
  return name;
}

export function requireDecimals(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0 || value > 255) {
    throw new Error("Decimals must be an integer from 0 to 255");
  }
  return value;
}

export function requireThreshold(value: unknown, signerCount: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error("Threshold must be a positive integer");
  }
  if (value > signerCount) {
    throw new Error("Threshold exceeds signer count");
  }
  return value;
}

export function requireSignerPubKeys(value: unknown): string {
  if (value === undefined || value === "") {
    return "";
  }
  if (typeof value !== "string") {
    throw new Error("Signer public keys must be hex");
  }
  const keys = value
    .split(",")
    .map((key) => key.trim())
    .filter(Boolean);
  if (keys.length > MAX_SIGNER_KEYS) {
    throw new Error("Too many signer public keys");
  }
  return keys
    .map((key) => {
      const hex = normalizeHex(key);
      if (hex.length < 64 || hex.length > 132) {
        throw new Error("Invalid signer public key hex");
      }
      return hex;
    })
    .join(",");
}

export function requireRequestId(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z]{2,12}-[0-9a-f]{32}$/.test(value)) {
    throw new Error("Invalid request id");
  }
  return value;
}
