import { describe, expect, it } from 'vitest';
import pqrng, {
  ErrorCode,
  PqRngError,
  base64UrlDecode,
  base64UrlEncode,
  bytesToHex,
  choice,
  createGenerator,
  defaultEntropySource,
  getDefaultGenerator,
  hexToBytes,
  latticeConditionedEntropySource,
  randomBase64Url,
  randomBelow,
  randomBigInt,
  randomBigIntInRange,
  randomBoolean,
  randomBytes,
  randomFloat,
  randomHex,
  randomInt,
  randomIntInclusive,
  randomString,
  randomUint32,
  reseed,
  sample,
  shuffle,
  stats,
  systemEntropySource,
  uuid,
  uuidV4,
  uuidV7,
} from '../src/index.js';
import type { EntropySource } from '../src/index.js';

describe('package facade', () => {
  it('exposes working free functions backed by a shared generator', () => {
    expect(randomBytes(16)).toHaveLength(16);
    const value = randomInt(1, 7);
    expect(value).toBeGreaterThanOrEqual(1);
    expect(value).toBeLessThan(7);
    expect(randomString(10)).toHaveLength(10);
    expect(/^[0-9a-f-]{36}$/.test(uuidV4())).toBe(true);
  });

  it('exposes every generator method as a free function', () => {
    expect(randomUint32()).toBeGreaterThanOrEqual(0);
    expect(randomBelow(10)).toBeLessThan(10);
    expect(randomIntInclusive(1, 1)).toBe(1);
    expect(randomBigInt(2n ** 64n)).toBeLessThan(2n ** 64n);
    expect(randomBigIntInRange(10n, 20n)).toBeGreaterThanOrEqual(10n);
    expect(randomFloat()).toBeLessThan(1);
    expect(typeof randomBoolean()).toBe('boolean');
    expect(randomHex(4)).toHaveLength(8);
    expect(base64UrlDecode(randomBase64Url(6))).toHaveLength(6);
    expect(/^[0-9a-f-]{36}$/.test(uuid())).toBe(true);
    expect(/-7[0-9a-f]{3}-/.test(uuidV7())).toBe(true);
    expect(['x', 'y']).toContain(choice(['x', 'y']));
    expect(sample([1, 2, 3, 4], 2)).toHaveLength(2);
    expect(shuffle([1, 2, 3]).sort()).toEqual([1, 2, 3]);
    const before = stats().reseeds;
    reseed('facade-context');
    expect(stats().reseeds).toBe(before + 1);
  });

  it('reuses a single default generator instance', () => {
    expect(getDefaultGenerator()).toBe(getDefaultGenerator());
  });

  it('createGenerator yields an independent instance', () => {
    expect(createGenerator()).not.toBe(getDefaultGenerator());
  });

  it('default export mirrors the named functions', () => {
    expect(typeof pqrng.randomInt).toBe('function');
    expect(pqrng.randomBytes(8)).toHaveLength(8);
  });
});

describe('entropy sources', () => {
  it('the system source returns the requested bytes', () => {
    expect(systemEntropySource.name).toBe('system-csprng');
    expect(systemEntropySource.gather(32)).toHaveLength(32);
  });

  it('the lattice source conditions to length and varies between draws', () => {
    const source = latticeConditionedEntropySource('ML-KEM-768');
    expect(source.name).toContain('ML-KEM-768');
    const first = source.gather(48);
    const second = source.gather(48);
    expect(first).toHaveLength(48);
    expect(first).not.toEqual(second);
  });

  it('defaultEntropySource matches the strength to an ML-KEM set', () => {
    expect(defaultEntropySource(128).name).toContain('ML-KEM-512');
    expect(defaultEntropySource(256).name).toContain('ML-KEM-1024');
  });

  it('a custom entropy source is used and surfaced in stats', () => {
    const custom: EntropySource = {
      name: 'custom-source',
      gather: (n) => new Uint8Array(n).fill(0x2a),
    };
    const rng = createGenerator({ entropySource: custom });
    expect(rng.stats().entropySource).toBe('custom-source');
    expect(rng.randomBytes(8)).toHaveLength(8);
  });
});

describe('encoding utilities', () => {
  it('round-trips base64url', () => {
    const bytes = randomBytes(20);
    expect(base64UrlDecode(base64UrlEncode(bytes))).toEqual(bytes);
  });

  it('round-trips hex', () => {
    const bytes = randomBytes(20);
    expect(hexToBytes(bytesToHex(bytes))).toEqual(bytes);
  });

  it('rejects malformed base64url with an ENCODING error', () => {
    try {
      base64UrlDecode('not*valid*base64url');
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(PqRngError);
      expect((err as PqRngError).code).toBe(ErrorCode.ENCODING);
    }
  });
});

describe('error hierarchy', () => {
  it('carries a stable code, context, and cause', () => {
    const cause = new Error('root');
    const err = new PqRngError('wrapped', ErrorCode.ENCODING, { context: { field: 'x' }, cause });
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('PqRngError');
    expect(err.code).toBe(ErrorCode.ENCODING);
    expect(err.context).toEqual({ field: 'x' });
    expect(err.cause).toBe(cause);
  });
});
