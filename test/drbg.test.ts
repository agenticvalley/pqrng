import { describe, expect, it } from 'vitest';
import {
  DEFAULT_SECURITY_STRENGTH,
  SECURITY_STRENGTHS,
  SEEDLEN,
  ShakeDrbg,
  SUPPORTED_STRENGTHS,
  getStrengthProfile,
  isSecurityStrength,
  shake256Xof,
  ErrorCode,
  GeneratorStateError,
  UnsupportedStrengthError,
} from '../src/index.js';
import type { SecurityStrength } from '../src/index.js';

const entropy = new Uint8Array(32).fill(0xa5);
const nonce = new Uint8Array(16).fill(0x5a);

function makeDrbg(reseedInterval = 1024): ShakeDrbg {
  return new ShakeDrbg({ entropy, nonce, reseedInterval });
}

describe('shake256Xof', () => {
  it('produces exactly the requested number of bytes', () => {
    for (const length of [0, 1, 32, 100, 512]) {
      expect(shake256Xof(length, entropy)).toHaveLength(length);
    }
  });

  it('is deterministic for identical input', () => {
    expect(shake256Xof(64, entropy)).toEqual(shake256Xof(64, entropy));
  });

  it('domain-separates by input order and content', () => {
    const a = shake256Xof(32, Uint8Array.of(0x00), entropy);
    const b = shake256Xof(32, Uint8Array.of(0x01), entropy);
    expect(a).not.toEqual(b);
  });
});

describe('strength registry', () => {
  it('defaults to 256-bit strength', () => {
    expect(DEFAULT_SECURITY_STRENGTH).toBe(256);
  });

  it('uses a 512-bit (64-byte) working state', () => {
    expect(SEEDLEN).toBe(64);
  });

  it('lists exactly the three supported strengths', () => {
    expect([...SUPPORTED_STRENGTHS]).toEqual([128, 192, 256]);
  });

  it.each(SUPPORTED_STRENGTHS)('profile for %s meets the SP 800-90A entropy minimums', (strength) => {
    const profile = getStrengthProfile(strength);
    // At least `strength` bits of entropy and `strength / 2` bits of nonce.
    expect(profile.entropyBytes * 8).toBeGreaterThanOrEqual(strength);
    expect(profile.nonceBytes * 8).toBeGreaterThanOrEqual(strength / 2);
  });

  it('matches each strength to an ML-KEM parameter set', () => {
    expect(SECURITY_STRENGTHS[128].mlKem).toBe('ML-KEM-512');
    expect(SECURITY_STRENGTHS[192].mlKem).toBe('ML-KEM-768');
    expect(SECURITY_STRENGTHS[256].mlKem).toBe('ML-KEM-1024');
  });

  it('recognizes valid strengths and rejects others', () => {
    expect(isSecurityStrength(192)).toBe(true);
    expect(isSecurityStrength(200)).toBe(false);
    expect(isSecurityStrength('256')).toBe(false);
  });

  it('throws UnsupportedStrengthError for an unknown strength', () => {
    expect(() => getStrengthProfile(64 as SecurityStrength)).toThrowError(UnsupportedStrengthError);
  });
});

describe('ShakeDrbg', () => {
  it('is deterministic given identical seed material', () => {
    const a = makeDrbg().generate(64);
    const b = makeDrbg().generate(64);
    expect(a).toEqual(b);
    expect(a).toHaveLength(64);
  });

  it('advances state between generate calls', () => {
    const drbg = makeDrbg();
    expect(drbg.generate(32)).not.toEqual(drbg.generate(32));
  });

  it('diverges when additional input is supplied', () => {
    const plain = makeDrbg().generate(32);
    const withInput = makeDrbg().generate(32, new Uint8Array([1, 2, 3]));
    expect(plain).not.toEqual(withInput);
  });

  it('signals when a reseed is required and refuses to over-generate', () => {
    const drbg = makeDrbg(1);
    drbg.generate(8); // counter 1 -> 2
    expect(drbg.needsReseed()).toBe(true);
    try {
      drbg.generate(8);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(GeneratorStateError);
      expect((err as GeneratorStateError).code).toBe(ErrorCode.RESEED_REQUIRED);
    }
  });

  it('restores generation after reseeding, and reseeding changes the stream', () => {
    const drbg = makeDrbg(1);
    const before = drbg.generate(16);
    drbg.reseed(new Uint8Array(32).fill(0x11));
    expect(drbg.needsReseed()).toBe(false);
    const after = drbg.generate(16);
    expect(after).not.toEqual(before);
  });

  it('throws after being destroyed', () => {
    const drbg = makeDrbg();
    drbg.destroy();
    expect(() => drbg.generate(1)).toThrowError(GeneratorStateError);
    expect(() => drbg.reseed(entropy)).toThrowError(GeneratorStateError);
  });
});
