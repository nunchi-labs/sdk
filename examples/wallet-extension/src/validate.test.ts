import { describe, it, expect } from "vitest";
import { bech32 } from "bech32";
import {
  normalizeHex,
  requireAddress,
  requireAmount,
  requireCoinHex,
  requireCurve,
  requireDecimals,
  requirePassword,
  requirePrivateKeyHex,
  requireRequestId,
  requireSignerPubKeys,
  requireThreshold,
  requireTokenName,
  requireTokenSymbol,
  U128_MAX,
} from "./validate";

const ZERO_ADDRESS = bech32.encode("nch", bech32.toWords(new Uint8Array(32)));

describe("normalizeHex", () => {
  it("strips 0x and lowercases", () => {
    expect(normalizeHex("0xAa")).toBe("aa");
  });

  it("rejects odd length and non-hex", () => {
    expect(() => normalizeHex("abc")).toThrow("even length");
    expect(() => normalizeHex("zz")).toThrow("invalid characters");
  });
});

describe("requireCoinHex", () => {
  it("accepts 32-byte hex", () => {
    expect(requireCoinHex(`0x${"Ab".repeat(32)}`)).toBe("ab".repeat(32));
  });

  it("rejects the wrong length", () => {
    expect(() => requireCoinHex("aa".repeat(16))).toThrow("32 bytes hex");
  });
});

describe("requireAmount", () => {
  it("accepts whole numbers including zero", () => {
    expect(requireAmount("0")).toBe("0");
    expect(requireAmount("1000")).toBe("1000");
    expect(requireAmount(U128_MAX.toString())).toBe(U128_MAX.toString());
  });

  it("rejects decimals, signs, and overflow", () => {
    expect(() => requireAmount("1.0")).toThrow("whole number");
    expect(() => requireAmount("-1")).toThrow("whole number");
    expect(() => requireAmount("01")).toThrow("whole number");
    expect(() => requireAmount((U128_MAX + 1n).toString())).toThrow("u128");
  });
});

describe("requireAddress", () => {
  it("accepts a 32-byte nch bech32 address", () => {
    expect(requireAddress(` ${ZERO_ADDRESS} `)).toBe(ZERO_ADDRESS);
  });

  it("rejects the wrong hrp and garbage", () => {
    const words = bech32.toWords(new Uint8Array(32));
    expect(() => requireAddress(bech32.encode("eth", words))).toThrow("Invalid nch address");
    expect(() => requireAddress("nch1notanaddress")).toThrow("Invalid nch address");
  });
});

describe("requirePrivateKeyHex", () => {
  it("accepts tagged 33-byte keys", () => {
    expect(requirePrivateKeyHex(`0x${"11".repeat(33)}`)).toBe("11".repeat(33));
  });

  it("rejects short keys", () => {
    expect(() => requirePrivateKeyHex("aa".repeat(16))).toThrow("32 or 33 bytes");
  });
});

describe("requireCurve", () => {
  it("accepts the two wallet curves", () => {
    expect(requireCurve("Ed25519")).toBe("Ed25519");
    expect(requireCurve("Secp256r1")).toBe("Secp256r1");
  });

  it("rejects anything else", () => {
    expect(() => requireCurve("secp256k1")).toThrow("Unsupported curve");
  });
});

describe("requirePassword", () => {
  it("accepts a trimmed password of at least 8 characters", () => {
    expect(requirePassword("correct-password")).toBe("correct-password");
  });

  it("rejects short, padded, and control-character passwords", () => {
    expect(() => requirePassword("1234567")).toThrow("at least 8");
    expect(() => requirePassword("        ")).toThrow("invalid characters");
    expect(() => requirePassword(" password")).toThrow("invalid characters");
    expect(() => requirePassword("pass\nword")).toThrow("invalid characters");
  });
});

describe("requirePrivateKeyHex length", () => {
  it("rejects oversized keys", () => {
    expect(() => requirePrivateKeyHex("aa".repeat(64))).toThrow("32 or 33 bytes");
  });
});

describe("token fields", () => {
  it("accepts a normal symbol and name", () => {
    expect(requireTokenSymbol("WLT")).toBe("WLT");
    expect(requireTokenName("Wallet")).toBe("Wallet");
    expect(requireDecimals(6)).toBe(6);
  });

  it("rejects empty, huge, and non-integer token metadata", () => {
    expect(() => requireTokenSymbol("")).toThrow("required");
    expect(() => requireTokenSymbol("X".repeat(33))).toThrow("too long");
    expect(() => requireTokenSymbol("WLT!")).toThrow("invalid characters");
    expect(() => requireTokenName("")).toThrow("required");
    expect(() => requireDecimals(1.5)).toThrow("integer");
    expect(() => requireDecimals(256)).toThrow("integer");
  });
});

describe("policy fields", () => {
  it("accepts a 1-of-1 hex signer set", () => {
    const key = "11".repeat(33);
    expect(requireSignerPubKeys(key)).toBe(key);
    expect(requireThreshold(1, 1)).toBe(1);
  });

  it("rejects a threshold above the signer count", () => {
    expect(() => requireThreshold(2, 1)).toThrow("signer count");
    expect(() => requireThreshold(0, 1)).toThrow("positive integer");
  });
});

describe("requireRequestId", () => {
  it("accepts randomRequestId output", () => {
    expect(requireRequestId("conn-" + "ab".repeat(16))).toBe("conn-" + "ab".repeat(16));
  });

  it("rejects empty and path-like ids", () => {
    expect(() => requireRequestId("")).toThrow("Invalid request id");
    expect(() => requireRequestId("../popup.html")).toThrow("Invalid request id");
  });
});
