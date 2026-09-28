import { describe, expect, it } from 'vitest';
import {
  Alphabets,
  EmptyRangeError,
  ErrorCode,
  GeneratorStateError,
  InvalidArgumentError,
  InvalidSeedError,
  type PostQuantumRandom,
  createGenerator,
} from '../src/index.js';
import { base64UrlDecode } from '../src/index.js';

const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const UUID_V7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** A fresh deterministic generator, so every assertion is reproducible. */
function seeded(label = 'unit-test-seed'): PostQuantumRandom {
  return createGenerator({ seed: new TextEncoder().encode(label) });
}

describe('construction', () => {
  it('defaults to 256-bit strength and a lattice-conditioned source', () => {
    const rng = createGenerator();
    const stats = rng.stats();
    expect(stats.strength).toBe(256);
    expect(stats.entropySource).toContain('lattice-conditioned');
    expect(stats.deterministic).toBe(false);
  });

  it.each([128, 192, 256] as const)('honours the requested strength %s', (strength) => {
    expect(createGenerator({ strength }).strength).toBe(strength);
  });

  it('rejects an unsupported strength', () => {
    // @ts-expect-error — intentionally invalid at the type level too.
    expect(() => createGenerator({ strength: 64 })).toThrow();
  });

  it('rejects an empty deterministic seed', () => {
    expect(() => createGenerator({ seed: new Uint8Array(0) })).toThrowError(InvalidSeedError);
  });
});

describe('determinism', () => {
  it('produces an identical stream for the same seed', () => {
    const a = seeded();
    const b = seeded();
    expect(a.randomBytes(32)).toEqual(b.randomBytes(32));
    expect(a.randomInt(0, 1_000_000)).toBe(b.randomInt(0, 1_000_000));
    expect(a.uuidV4()).toBe(b.uuidV4());
  });

  it('diverges when the personalization differs', () => {
    const seed = new TextEncoder().encode('same-seed');
    const a = createGenerator({ seed, personalization: 'tenant-a' });
    const b = createGenerator({ seed, personalization: 'tenant-b' });
    expect(a.randomBytes(16)).not.toEqual(b.randomBytes(16));
  });
});

describe('bytes & integers', () => {
  it('returns the requested number of bytes', () => {
    expect(seeded().randomBytes(0)).toHaveLength(0);
    expect(seeded().randomBytes(48)).toHaveLength(48);
  });

  it('rejects a negative length', () => {
    expect(() => seeded().randomBytes(-1)).toThrowError(InvalidArgumentError);
  });

  it('randomUint32 stays within 32 bits', () => {
    const rng = seeded();
    for (let i = 0; i < 1000; i++) {
      const value = rng.randomUint32();
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThanOrEqual(0xffffffff);
      expect(Number.isInteger(value)).toBe(true);
    }
  });

  it('randomBelow(1) is always 0, and randomBelow(0) throws', () => {
    expect(seeded().randomBelow(1)).toBe(0);
    expect(() => seeded().randomBelow(0)).toThrowError(EmptyRangeError);
  });

  it('randomInt spans exactly [min, max)', () => {
    const rng = seeded();
    const seen = new Set<number>();
    for (let i = 0; i < 3000; i++) {
      const value = rng.randomInt(-3, 4);
      expect(value).toBeGreaterThanOrEqual(-3);
      expect(value).toBeLessThan(4);
      seen.add(value);
    }
    expect([...seen].sort((x, y) => x - y)).toEqual([-3, -2, -1, 0, 1, 2, 3]);
  });

  it('randomInt rejects an empty range', () => {
    expect(() => seeded().randomInt(5, 5)).toThrowError(EmptyRangeError);
    expect(() => seeded().randomInt(9, 2)).toThrowError(EmptyRangeError);
  });

  it('randomIntInclusive includes both endpoints', () => {
    const rng = seeded();
    let sawMin = false;
    let sawMax = false;
    for (let i = 0; i < 2000; i++) {
      const value = rng.randomIntInclusive(1, 3);
      expect(value).toBeGreaterThanOrEqual(1);
      expect(value).toBeLessThanOrEqual(3);
      if (value === 1) sawMin = true;
      if (value === 3) sawMax = true;
    }
    expect(sawMin && sawMax).toBe(true);
  });

  it('supports bigint ranges beyond the safe-integer limit', () => {
    const rng = seeded();
    const max = 2n ** 200n;
    for (let i = 0; i < 500; i++) {
      const value = rng.randomBigInt(max);
      expect(value).toBeGreaterThanOrEqual(0n);
      expect(value).toBeLessThan(max);
    }
    const lo = 10n ** 30n;
    const hi = lo + 1000n;
    const ranged = rng.randomBigIntInRange(lo, hi);
    expect(ranged).toBeGreaterThanOrEqual(lo);
    expect(ranged).toBeLessThan(hi);
  });

  it('rejects invalid bigint bounds', () => {
    expect(() => seeded().randomBigInt(0n)).toThrowError(EmptyRangeError);
    expect(() => seeded().randomBigIntInRange(5n, 5n)).toThrowError(EmptyRangeError);
  });
});

describe('floats & booleans', () => {
  it('randomFloat stays in [0, 1) and varies', () => {
    const rng = seeded();
    const values = new Set<number>();
    for (let i = 0; i < 5000; i++) {
      const value = rng.randomFloat();
      expect(value).toBeGreaterThanOrEqual(0);
      expect(value).toBeLessThan(1);
      values.add(value);
    }
    expect(values.size).toBeGreaterThan(4950); // essentially all distinct
  });

  it('randomBoolean respects deterministic probabilities', () => {
    expect(seeded().randomBoolean(0)).toBe(false);
    expect(seeded().randomBoolean(1)).toBe(true);
    expect(() => seeded().randomBoolean(1.5)).toThrowError(InvalidArgumentError);
  });

  it('randomBoolean() is roughly fair', () => {
    const rng = seeded();
    let trues = 0;
    const n = 10000;
    for (let i = 0; i < n; i++) if (rng.randomBoolean()) trues++;
    expect(trues / n).toBeGreaterThan(0.46);
    expect(trues / n).toBeLessThan(0.54);
  });
});

describe('strings & encodings', () => {
  it('randomString has the requested length and alphabet', () => {
    const rng = seeded();
    expect(rng.randomString(0)).toBe('');
    const digits = rng.randomString(50, { alphabet: Alphabets.numeric });
    expect(digits).toHaveLength(50);
    expect(/^[0-9]{50}$/.test(digits)).toBe(true);
  });

  it('randomString rejects an empty alphabet', () => {
    expect(() => seeded().randomString(4, { alphabet: '' })).toThrowError(EmptyRangeError);
  });

  it('randomHex is lowercase hex of the right length', () => {
    const hex = seeded().randomHex(16);
    expect(hex).toHaveLength(32);
    expect(/^[0-9a-f]{32}$/.test(hex)).toBe(true);
  });

  it('randomBase64Url round-trips to the requested byte count', () => {
    const token = seeded().randomBase64Url(24);
    expect(base64UrlDecode(token)).toHaveLength(24);
  });
});

describe('UUIDs', () => {
  it('mints well-formed, unique UUIDv4s', () => {
    const rng = seeded();
    const seen = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      const uuid = rng.uuidV4();
      expect(UUID_V4.test(uuid)).toBe(true);
      seen.add(uuid);
    }
    expect(seen.size).toBe(1000);
  });

  it('uuid() is an alias for uuidV4', () => {
    expect(UUID_V4.test(seeded().uuid())).toBe(true);
  });

  it('mints time-ordered UUIDv7s', () => {
    const rng = seeded();
    const early = rng.uuidV7({ clock: () => 1_000_000 });
    const late = rng.uuidV7({ clock: () => 2_000_000 });
    expect(UUID_V7.test(early)).toBe(true);
    expect(UUID_V7.test(late)).toBe(true);
    expect(early < late).toBe(true); // lexicographic order follows time
  });

  it('rejects a nonsensical clock', () => {
    expect(() => seeded().uuidV7({ clock: () => -1 })).toThrowError(InvalidArgumentError);
  });
});

describe('collections', () => {
  it('choice returns a member and rejects empties', () => {
    const rng = seeded();
    const items = ['a', 'b', 'c'] as const;
    for (let i = 0; i < 100; i++) expect(items).toContain(rng.choice(items));
    expect(() => rng.choice([])).toThrowError(EmptyRangeError);
  });

  it('sample draws distinct members without replacement', () => {
    const rng = seeded();
    const population = Array.from({ length: 20 }, (_, i) => i);
    const drawn = rng.sample(population, 8);
    expect(drawn).toHaveLength(8);
    expect(new Set(drawn).size).toBe(8);
    for (const value of drawn) expect(population).toContain(value);
    expect(rng.sample(population, 0)).toEqual([]);
    expect(() => rng.sample(population, 21)).toThrowError(InvalidArgumentError);
  });

  it('shuffle is a permutation and leaves the input untouched', () => {
    const rng = seeded();
    const input = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    const frozen = [...input];
    const shuffled = rng.shuffle(input);
    expect(input).toEqual(frozen); // not mutated
    expect([...shuffled].sort((a, b) => a - b)).toEqual(frozen); // same multiset
  });

  it('shuffleInPlace mutates and returns the same array', () => {
    const rng = seeded();
    const array = [1, 2, 3, 4, 5, 6, 7, 8];
    const result = rng.shuffleInPlace(array);
    expect(result).toBe(array);
    expect([...array].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
  });
});

describe('uniformity', () => {
  it('randomBelow is close to uniform across buckets', () => {
    const rng = seeded('uniformity-seed');
    const buckets = 6;
    const draws = 30_000;
    const counts = new Array<number>(buckets).fill(0);
    for (let i = 0; i < draws; i++) counts[rng.randomBelow(buckets)]++;
    const expected = draws / buckets;
    for (const count of counts) {
      expect(count).toBeGreaterThan(expected * 0.9);
      expect(count).toBeLessThan(expected * 1.1);
    }
  });
});

describe('lifecycle', () => {
  it('reseed advances the reseed count and forbids it in deterministic mode', () => {
    const rng = createGenerator();
    const before = rng.stats().reseeds;
    rng.reseed('extra-context');
    expect(rng.stats().reseeds).toBe(before + 1);
    expect(rng.stats().reseedCounter).toBe(1);
    expect(() => seeded().reseed()).toThrowError(InvalidArgumentError);
  });

  it('auto-reseeds when the interval is reached', () => {
    const rng = createGenerator({ reseedInterval: 1, autoReseed: true });
    rng.randomBytes(1);
    rng.randomBytes(1);
    rng.randomBytes(1);
    expect(rng.stats().reseeds).toBeGreaterThan(0);
  });

  it('raises RESEED_REQUIRED when auto-reseed is disabled', () => {
    const rng = createGenerator({ reseedInterval: 1, autoReseed: false });
    rng.randomBytes(1);
    try {
      rng.randomBytes(1);
      expect.unreachable('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(GeneratorStateError);
      expect((err as GeneratorStateError).code).toBe(ErrorCode.RESEED_REQUIRED);
    }
    rng.reseed();
    expect(rng.randomBytes(1)).toHaveLength(1); // recovered
  });

  it('throws after destroy, and destroy is idempotent', () => {
    const rng = seeded();
    rng.destroy();
    expect(rng.stats().destroyed).toBe(true);
    expect(() => rng.randomBytes(1)).toThrowError(GeneratorStateError);
    expect(() => rng.destroy()).not.toThrow();
  });
});
