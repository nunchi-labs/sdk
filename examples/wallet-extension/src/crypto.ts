import { pbkdf2 } from "@noble/hashes/pbkdf2";
import { sha256 } from "@noble/hashes/sha256";

const ITERATIONS = 100000;
const KEY_LENGTH = 32;

export async function deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  return pbkdf2(sha256, password, salt, { c: ITERATIONS, dkLen: KEY_LENGTH });
}

export function generateSalt(): Uint8Array {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  return salt;
}

export async function encryptPrivateKey(
  privateKeyHex: string,
  password: string
): Promise<{ encrypted: string; salt: string }> {
  const salt = generateSalt();
  const key = await deriveKey(password, salt);

  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);

  const cryptoKey = await crypto.subtle.importKey("raw", key as BufferSource, { name: "AES-GCM" }, false, ["encrypt"]);

  const privateKeyBytes = hexToBytes(privateKeyHex);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, cryptoKey, privateKeyBytes as BufferSource);

  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);

  return {
    encrypted: bytesToHex(combined),
    salt: bytesToHex(salt),
  };
}

export async function decryptPrivateKey(
  encryptedHex: string,
  saltHex: string,
  password: string
): Promise<string> {
  const salt = hexToBytes(saltHex);
  const key = await deriveKey(password, salt);

  const combined = hexToBytes(encryptedHex);
  const iv = combined.slice(0, 12);
  const encrypted = combined.slice(12);

  const cryptoKey = await crypto.subtle.importKey("raw", key as BufferSource, { name: "AES-GCM" }, false, ["decrypt"]);

  try {
    const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as BufferSource }, cryptoKey, encrypted as BufferSource);
    return bytesToHex(new Uint8Array(decrypted));
  } catch {
    throw new Error("Invalid password");
  }
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith("0x")) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
