import { describe, it, expect } from 'vitest';
import { encryptPrivateKey, decryptPrivateKey, generateSalt, hexToBytes } from './crypto';

describe('crypto', () => {
  it('should reject wrong password', async () => {
    const privateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const password = 'correct-password';
    
    const { encrypted, salt } = await encryptPrivateKey(privateKey, password);
    
    await expect(
      decryptPrivateKey(encrypted, salt, 'wrong-password')
    ).rejects.toThrow('Invalid password');
  });

  it('should round-trip with correct password', async () => {
    const privateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const password = 'test-password-123';
    
    const { encrypted, salt } = await encryptPrivateKey(privateKey, password);
    const decrypted = await decryptPrivateKey(encrypted, salt, password);
    
    expect(decrypted).toBe(privateKey);
  });

  it('should produce unique salts', () => {
    const salt1 = generateSalt();
    const salt2 = generateSalt();
    
    expect(salt1).not.toEqual(salt2);
    expect(salt1.length).toBe(32);
    expect(salt2.length).toBe(32);
  });

  it('should produce unique ciphertexts for same key', async () => {
    const privateKey = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
    const password = 'same-password';
    
    const result1 = await encryptPrivateKey(privateKey, password);
    const result2 = await encryptPrivateKey(privateKey, password);
    
    expect(result1.encrypted).not.toBe(result2.encrypted);
    expect(result1.salt).not.toBe(result2.salt);
  });

  it('should reject odd-length hex in hexToBytes', () => {
    expect(() => hexToBytes('abc')).toThrow('even length');
  });

  it('should reject non-hex characters', () => {
    expect(() => hexToBytes('xyz123')).toThrow('invalid characters');
  });
});
