const META_STORAGE_KEY = 'nunchi.wallets.v1';
const SESSION_STORAGE_KEY = 'nunchi.session.v1';
const PASSKEY_TIMEOUT_MS = 90_000;
const SECP256R1_SCHEME = 1;
const RAW_P256_PUBLIC_KEY_BYTES = 65;
const COMPRESSED_P256_PUBLIC_KEY_BYTES = 33;
const TRANSACTION_PUBLIC_KEY_BYTES = 34;
const RAW_SIGNATURE_BYTES = 64;
const AUTHENTICATOR_DATA_BYTES = 256;
const CLIENT_DATA_JSON_BYTES = 512;
const P256_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');

export interface WalletProfile {
    readonly publicKeyHex: string;
    readonly credentialId: string;
    readonly createdAt: number;
}

export interface ActiveWallet extends WalletProfile {
    readonly publicKey: Uint8Array;
    readonly sign: (message: Uint8Array) => Promise<Uint8Array>;
}

export function listWallets(): WalletProfile[] {
    return readProfiles().sort((a, b) => b.createdAt - a.createdAt);
}

export async function createPasskeyWallet(displayName = 'nunchi-wallet'): Promise<ActiveWallet> {
    assertWalletSupport();
    const credential = await createPasskey(displayName);
    const credentialId = encodeBase64Url(new Uint8Array(credential.rawId));
    const publicKey = await transactionPublicKey(credential);
    const publicKeyHex = toHex(publicKey);
    const profile = { publicKeyHex, credentialId, createdAt: Date.now() };
    writeProfiles([profile, ...readProfiles().filter((item) => item.publicKeyHex !== publicKeyHex)]);
    writeSession(publicKeyHex);
    return activeWallet(profile);
}

export async function signWithPasskey(profile: WalletProfile, challenge: Uint8Array): Promise<Uint8Array> {
    return activeWallet(profile).then((wallet) => wallet.sign(challenge));
}

function activeWallet(profile: WalletProfile): ActiveWallet {
    const publicKey = fromHex(profile.publicKeyHex);
    return {
        ...profile,
        publicKey,
        sign: (message) => signWithPasskeyAssertion(profile, message),
    };
}

async function createPasskey(displayName: string): Promise<PublicKeyCredential> {
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: randomChallenge(),
            rp: { name: 'Nunchi Wallet' },
            user: {
                id: randomChallenge(),
                name: displayName,
                displayName,
            },
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            authenticatorSelection: {
                authenticatorAttachment: 'platform',
                residentKey: 'preferred',
                userVerification: 'required',
            },
            timeout: PASSKEY_TIMEOUT_MS,
            attestation: 'none',
        },
    });
    if (!(credential instanceof PublicKeyCredential)) {
        throw new Error('passkey creation was cancelled');
    }
    return credential;
}

async function signWithPasskeyAssertion(profile: WalletProfile, challenge: Uint8Array): Promise<Uint8Array> {
    const assertion = await getPasskeyAssertion([profile], challenge.buffer);
    if (!(assertion instanceof PublicKeyCredential)) {
        throw new Error('passkey signing was cancelled');
    }
    const credentialId = encodeBase64Url(new Uint8Array(assertion.rawId));
    if (credentialId !== profile.credentialId) {
        throw new Error('passkey returned a different credential');
    }
    const response = assertion.response;
    if (!(response instanceof AuthenticatorAssertionResponse)) {
        throw new Error('passkey did not return an assertion');
    }
    return encodeTransactionSignature(
        normalizeP256Signature(parseDerSignature(new Uint8Array(response.signature))),
        new Uint8Array(response.authenticatorData),
        new Uint8Array(response.clientDataJSON),
    );
}

async function getPasskeyAssertion(profiles: WalletProfile[], challenge: ArrayBuffer): Promise<Credential | null> {
    return navigator.credentials.get({
        publicKey: {
            challenge,
            timeout: PASSKEY_TIMEOUT_MS,
            userVerification: 'required',
            allowCredentials: profiles.map((profile) => ({
                type: 'public-key',
                id: decodeBase64Url(profile.credentialId),
                transports: ['internal'],
            })),
        },
    });
}

async function transactionPublicKey(credential: PublicKeyCredential): Promise<Uint8Array> {
    const response = credential.response;
    if (!(response instanceof AuthenticatorAttestationResponse)) {
        throw new Error('passkey did not return attestation data');
    }
    const spki = response.getPublicKey?.();
    if (!spki) {
        throw new Error('this browser cannot expose the passkey public key');
    }
    const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
    const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    const compressed = compressP256PublicKey(raw);
    const publicKey = new Uint8Array(TRANSACTION_PUBLIC_KEY_BYTES);
    publicKey[0] = SECP256R1_SCHEME;
    publicKey.set(compressed, 1);
    return publicKey;
}

function encodeTransactionSignature(
    rawSignature: Uint8Array,
    authenticatorData: Uint8Array,
    clientDataJSON: Uint8Array,
): Uint8Array {
    if (authenticatorData.length > AUTHENTICATOR_DATA_BYTES || clientDataJSON.length > CLIENT_DATA_JSON_BYTES) {
        throw new Error('passkey payload is too large');
    }
    const out = new Uint8Array(1 + RAW_SIGNATURE_BYTES + 2 + authenticatorData.length + 2 + clientDataJSON.length);
    out[0] = SECP256R1_SCHEME;
    out.set(rawSignature, 1);
    writeU16Be(out, 1 + RAW_SIGNATURE_BYTES, authenticatorData.length);
    const clientDataLengthOffset = 1 + RAW_SIGNATURE_BYTES + 2 + authenticatorData.length;
    out.set(authenticatorData, 1 + RAW_SIGNATURE_BYTES + 2);
    writeU16Be(out, clientDataLengthOffset, clientDataJSON.length);
    out.set(clientDataJSON, clientDataLengthOffset + 2);
    return out;
}

function compressP256PublicKey(raw: Uint8Array): Uint8Array {
    const compressed = new Uint8Array(COMPRESSED_P256_PUBLIC_KEY_BYTES);
    compressed[0] = raw[RAW_P256_PUBLIC_KEY_BYTES - 1] % 2 === 0 ? 2 : 3;
    compressed.set(raw.slice(1, 33), 1);
    return compressed;
}

function parseDerSignature(signature: Uint8Array): Uint8Array {
    if (signature.length < 8 || signature[0] !== 0x30) {
        throw new Error('passkey returned a malformed ECDSA signature');
    }
    let offset = 2;
    if (signature[1] & 0x80) {
        offset = 3;
    }
    const r = readDerInteger(signature, offset);
    const s = readDerInteger(signature, r.nextOffset);
    const raw = new Uint8Array(RAW_SIGNATURE_BYTES);
    raw.set(r.value, 32 - r.value.length);
    raw.set(s.value, 64 - s.value.length);
    return raw;
}

function readDerInteger(signature: Uint8Array, offset: number): { value: Uint8Array; nextOffset: number } {
    const length = signature[offset + 1];
    const start = offset + 2;
    let value = signature.slice(start, start + length);
    while (value.length > 0 && value[0] === 0) {
        value = value.slice(1);
    }
    return { value, nextOffset: start + length };
}

function normalizeP256Signature(signature: Uint8Array): Uint8Array {
    const s = readBigEndian(signature.slice(32));
    if (s <= P256_ORDER / 2n) {
        return signature;
    }
    const normalized = new Uint8Array(signature);
    writeBigEndian(normalized, 32, P256_ORDER - s);
    return normalized;
}

function assertWalletSupport() {
    if (!window.isSecureContext) throw new Error('passkeys require a secure context');
    if (!navigator.credentials || !window.PublicKeyCredential) throw new Error('passkeys are unavailable');
    if (!crypto.subtle) throw new Error('WebCrypto is unavailable');
}

function randomChallenge(): ArrayBuffer {
    const challenge = new Uint8Array(32);
    crypto.getRandomValues(challenge);
    return challenge.buffer;
}

function readProfiles(): WalletProfile[] {
    const raw = window.localStorage.getItem(META_STORAGE_KEY);
    if (!raw) return [];
    try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function writeProfiles(profiles: WalletProfile[]) {
    window.localStorage.setItem(META_STORAGE_KEY, JSON.stringify(profiles));
}

function writeSession(publicKeyHex: string) {
    window.localStorage.setItem(SESSION_STORAGE_KEY, publicKeyHex);
}

function toHex(bytes: Uint8Array): string {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function fromHex(value: string): Uint8Array {
    const out = new Uint8Array(value.length / 2);
    for (let index = 0; index < out.length; index += 1) {
        out[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
    }
    return out;
}

function writeU16Be(target: Uint8Array, offset: number, value: number) {
    target[offset] = (value >> 8) & 0xff;
    target[offset + 1] = value & 0xff;
}

function readBigEndian(bytes: Uint8Array): bigint {
    let value = 0n;
    for (const byte of bytes) {
        value = (value << 8n) + BigInt(byte);
    }
    return value;
}

function writeBigEndian(target: Uint8Array, offset: number, value: bigint) {
    for (let index = 31; index >= 0; index -= 1) {
        target[offset + index] = Number(value & 0xffn);
        value >>= 8n;
    }
}

function encodeBase64Url(bytes: Uint8Array): string {
    let value = btoa(String.fromCharCode(...bytes));
    value = value.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
    return value;
}

function decodeBase64Url(value: string): ArrayBuffer {
    const padded = value.replaceAll('-', '+').replaceAll('_', '/');
    const binary = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), '='));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }
    return bytes.buffer;
}
