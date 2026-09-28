/**
 * @packageDocumentation
 * The high-level generator.
 *
 * {@link PostQuantumRandom} wraps the SHAKE256 DRBG in an ergonomic, familiar
 * surface — bytes, integers, ranges, floats, booleans, strings, hex, base64url,
 * UUIDs, and collection helpers (`choice`, `sample`, `shuffle`) — the same shape
 * you would reach for from `Math.random`, `crypto.randomInt`, or a utility
 * library, but every byte traces back to a post-quantum primitive.
 *
 * ## Unbiased by construction
 *
 * The subtle part of any RNG API is turning uniform *bytes* into uniform *values*
 * over an arbitrary range without introducing modulo bias. Every bounded routine
 * here funnels through {@link PostQuantumRandom.randomBigInt} rejection sampling,
 * which draws just enough bytes, masks to the range's bit-length, and rejects
 * out-of-range candidates — so the distribution is exactly uniform, at the cost
 * of fewer than two draws on average.
 */

import { EmptyRangeError, ErrorCode, GeneratorStateError, InvalidArgumentError, InvalidSeedError } from './errors.js';
import { ShakeDrbg } from './crypto/drbg.js';
import { defaultEntropySource, systemEntropySource, type EntropySource } from './crypto/entropy.js';
import {
  DEFAULT_SECURITY_STRENGTH,
  getStrengthProfile,
  type SecurityStrength,
  type StrengthProfile,
} from './crypto/strength.js';
import type { GeneratorOptions, GeneratorStats, RandomStringOptions, UuidV7Options } from './types.js';
import {
  base64UrlEncode,
  bytesToBigIntBE,
  bytesToHex,
  copyBytes,
  readUint32BE,
  systemClock,
  utf8ToBytes,
  wipe,
  type Clock,
} from './utils/index.js';

/** An empty byte string, reused to avoid per-call allocation. */
const EMPTY = new Uint8Array(0);

/**
 * Ready-made alphabets for {@link PostQuantumRandom.randomString}.
 *
 * All are chosen so that character selection stays cheap and unbiased; the
 * power-of-two alphabets (`hex`, `base64url`) never trigger a rejection.
 */
export const Alphabets = {
  /** URL-safe base64 alphabet (64 chars): `A–Z a–z 0–9 - _`. */
  base64url: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  /** Bitcoin-style base58 (58 chars): no `0`, `O`, `I`, or `l` to avoid look-alikes. */
  base58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
  /** Lowercase hexadecimal (16 chars). */
  hex: '0123456789abcdef',
  /** Letters and digits (62 chars). */
  alphanumeric: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
  /** Decimal digits (10 chars). */
  numeric: '0123456789',
  /** Lowercase ASCII letters (26 chars). */
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  /** Uppercase ASCII letters (26 chars). */
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
} as const;

/** Normalize an optional string / bytes value into bytes. */
function toBytes(value: Uint8Array | string | undefined): Uint8Array {
  if (value === undefined) {
    return EMPTY;
  }
  return typeof value === 'string' ? utf8ToBytes(value) : value;
}

/** Assert that `value` is a non-negative integer suitable as a length/count. */
function assertLength(value: number, name: string): void {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0) {
    throw new InvalidArgumentError(`${name} must be a non-negative integer`, { context: { [name]: String(value) } });
  }
}

/** Assert that `value` is a safe integer (usable as a numeric bound). */
function assertSafeInteger(value: number, name: string): void {
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
    throw new InvalidArgumentError(`${name} must be a safe integer`, { context: { [name]: String(value) } });
  }
}

/**
 * A post-quantum cryptographically secure random number generator.
 *
 * Construct one with {@link PostQuantumRandom.create} (or `new`), then call the
 * `random*` methods. Instances are stateful and cheap to keep around; a single
 * shared instance per process is the common pattern (that is exactly what the
 * package-level facade functions use).
 *
 * @example
 * ```ts
 * const rng = PostQuantumRandom.create();
 * rng.randomInt(1, 7);          // a fair d6: 1..6
 * rng.randomString(21);         // a URL-safe token
 * rng.uuidV4();                 // an RFC 9562 UUIDv4
 * rng.shuffle([1, 2, 3, 4, 5]); // an unbiased permutation
 * ```
 */
export class PostQuantumRandom {
  /** The configured security strength in bits. */
  public readonly strength: SecurityStrength;

  private readonly profile: StrengthProfile;
  private readonly entropySource: EntropySource;
  private readonly entropySourceName: string;
  private readonly deterministic: boolean;
  private readonly autoReseed: boolean;
  private readonly reseedInterval: number;
  private readonly clock: Clock;
  private readonly drbg: ShakeDrbg;

  private reseeds = 0;
  private bytesGenerated = 0;
  private destroyed = false;

  /**
   * @param options - {@link GeneratorOptions}. All fields are optional; the
   *   defaults yield a 256-bit-strength, lattice-conditioned, auto-reseeding
   *   generator.
   */
  public constructor(options: GeneratorOptions = {}) {
    const strength = options.strength ?? DEFAULT_SECURITY_STRENGTH;
    this.profile = getStrengthProfile(strength);
    this.strength = strength;
    this.clock = options.clock ?? systemClock;
    this.deterministic = options.seed !== undefined;
    this.entropySource = options.entropySource ?? defaultEntropySource(strength);
    this.entropySourceName = this.deterministic ? 'deterministic-seed' : this.entropySource.name;

    // A deterministic generator must never reseed (that would break its
    // reproducibility), so its interval is effectively infinite.
    this.reseedInterval = this.deterministic
      ? Number.MAX_SAFE_INTEGER
      : (options.reseedInterval ?? this.profile.reseedInterval);
    this.autoReseed = this.deterministic ? false : (options.autoReseed ?? true);

    const personalization = toBytes(options.personalization);
    const { entropy, nonce } = this.gatherInstantiationSeed(options.seed);
    this.drbg = new ShakeDrbg({ entropy, nonce, personalization, reseedInterval: this.reseedInterval });
    // The instantiate call above has already absorbed the seed; wipe our copies.
    wipe(entropy, nonce);
  }

  /**
   * Construct a generator. A thin, discoverable alias for the constructor.
   *
   * @param options - {@link GeneratorOptions}.
   */
  public static create(options: GeneratorOptions = {}): PostQuantumRandom {
    return new PostQuantumRandom(options);
  }

  // --- Bytes ---------------------------------------------------------------

  /**
   * Return `length` fresh pseudorandom bytes.
   *
   * @param length - Number of bytes (≥ 0).
   * @returns A new `Uint8Array` of exactly `length` bytes.
   */
  public randomBytes(length: number): Uint8Array {
    assertLength(length, 'length');
    return this.draw(length);
  }

  /** Return a uniform unsigned 32-bit integer in `0 … 2^32 − 1`. */
  public randomUint32(): number {
    return readUint32BE(this.draw(4));
  }

  // --- Integers ------------------------------------------------------------

  /**
   * Return a uniform integer in `[0, maxExclusive)`, free of modulo bias.
   *
   * @param maxExclusive - Exclusive upper bound; a safe integer `> 0`.
   */
  public randomBelow(maxExclusive: number): number {
    assertSafeInteger(maxExclusive, 'maxExclusive');
    if (maxExclusive <= 0) {
      throw new EmptyRangeError('maxExclusive must be greater than 0', { context: { maxExclusive } });
    }
    return Number(this.uniformBigInt(BigInt(maxExclusive)));
  }

  /**
   * Return a uniform integer in `[minInclusive, maxExclusive)`.
   *
   * @param minInclusive - Inclusive lower bound (safe integer).
   * @param maxExclusive - Exclusive upper bound (safe integer), strictly greater than `minInclusive`.
   */
  public randomInt(minInclusive: number, maxExclusive: number): number {
    assertSafeInteger(minInclusive, 'minInclusive');
    assertSafeInteger(maxExclusive, 'maxExclusive');
    if (maxExclusive <= minInclusive) {
      throw new EmptyRangeError('maxExclusive must be greater than minInclusive', {
        context: { minInclusive, maxExclusive },
      });
    }
    const span = BigInt(maxExclusive) - BigInt(minInclusive);
    // Add in BigInt space so a wide span cannot lose precision before the result
    // (which always lands within the safe-integer range) is narrowed back.
    return Number(BigInt(minInclusive) + this.uniformBigInt(span));
  }

  /**
   * Return a uniform integer in `[min, max]` — both bounds inclusive.
   *
   * @param min - Inclusive lower bound (safe integer).
   * @param max - Inclusive upper bound (safe integer), `≥ min`.
   */
  public randomIntInclusive(min: number, max: number): number {
    assertSafeInteger(min, 'min');
    assertSafeInteger(max, 'max');
    if (max < min) {
      throw new EmptyRangeError('max must be greater than or equal to min', { context: { min, max } });
    }
    const span = BigInt(max) - BigInt(min) + 1n;
    return Number(BigInt(min) + this.uniformBigInt(span));
  }

  /**
   * Return a uniform {@link BigInt} in `[0, maxExclusive)`.
   *
   * The workhorse behind every bounded integer helper. Use it directly when the
   * range exceeds `Number.MAX_SAFE_INTEGER`.
   *
   * @param maxExclusive - Exclusive upper bound; a `bigint > 0`.
   */
  public randomBigInt(maxExclusive: bigint): bigint {
    if (typeof maxExclusive !== 'bigint') {
      throw new InvalidArgumentError('maxExclusive must be a bigint', { context: { type: typeof maxExclusive } });
    }
    if (maxExclusive <= 0n) {
      throw new EmptyRangeError('maxExclusive must be greater than 0', {
        context: { maxExclusive: String(maxExclusive) },
      });
    }
    return this.uniformBigInt(maxExclusive);
  }

  /**
   * Return a uniform {@link BigInt} in `[minInclusive, maxExclusive)`.
   *
   * @param minInclusive - Inclusive lower bound.
   * @param maxExclusive - Exclusive upper bound, strictly greater than `minInclusive`.
   */
  public randomBigIntInRange(minInclusive: bigint, maxExclusive: bigint): bigint {
    if (typeof minInclusive !== 'bigint' || typeof maxExclusive !== 'bigint') {
      throw new InvalidArgumentError('bounds must be bigints');
    }
    if (maxExclusive <= minInclusive) {
      throw new EmptyRangeError('maxExclusive must be greater than minInclusive', {
        context: { minInclusive: String(minInclusive), maxExclusive: String(maxExclusive) },
      });
    }
    return minInclusive + this.uniformBigInt(maxExclusive - minInclusive);
  }

  // --- Floats & booleans ---------------------------------------------------

  /**
   * Return a uniform double in `[0, 1)` with full 53-bit mantissa precision.
   *
   * Uses the standard "53 significant bits over `2^53`" construction, so every
   * representable double in the interval is reachable — unlike the common
   * `bytes / 2^n` shortcut, which leaves gaps.
   */
  public randomFloat(): number {
    const bytes = this.draw(8);
    // 27 high bits + 26 low bits = 53 bits of significand.
    const high = readUint32BE(bytes, 0) >>> 5;
    const low = readUint32BE(bytes, 4) >>> 6;
    return (high * 2 ** 26 + low) / 2 ** 53;
  }

  /**
   * Return a random boolean.
   *
   * @param probability - Probability of `true`, in `[0, 1]`. Defaults to `0.5`,
   *   which is decided by a single unbiased bit.
   */
  public randomBoolean(probability = 0.5): boolean {
    if (typeof probability !== 'number' || Number.isNaN(probability) || probability < 0 || probability > 1) {
      throw new InvalidArgumentError('probability must be a number in [0, 1]', {
        context: { probability: String(probability) },
      });
    }
    if (probability === 0) {
      return false;
    }
    if (probability === 1) {
      return true;
    }
    if (probability === 0.5) {
      // A single low bit is exactly a fair coin — cheaper than a full float.
      return ((this.draw(1)[0] ?? 0) & 1) === 1;
    }
    return this.randomFloat() < probability;
  }

  // --- Strings & encodings -------------------------------------------------

  /**
   * Return a random string of `length` characters drawn uniformly from an alphabet.
   *
   * @param length - Number of characters (≥ 0).
   * @param options - {@link RandomStringOptions}; defaults to the base64url alphabet.
   */
  public randomString(length: number, options: RandomStringOptions = {}): string {
    assertLength(length, 'length');
    const alphabet = options.alphabet ?? Alphabets.base64url;
    if (alphabet.length === 0) {
      throw new EmptyRangeError('alphabet must contain at least one character');
    }
    const size = alphabet.length;
    const chars = new Array<string>(length);
    for (let i = 0; i < length; i++) {
      chars[i] = alphabet.charAt(this.randomBelow(size));
    }
    return chars.join('');
  }

  /**
   * Return `byteLength` random bytes encoded as a lowercase hex string.
   *
   * @param byteLength - Number of random bytes to encode (the string is twice as long).
   */
  public randomHex(byteLength: number): string {
    assertLength(byteLength, 'byteLength');
    return bytesToHex(this.draw(byteLength));
  }

  /**
   * Return `byteLength` random bytes encoded as an unpadded base64url string —
   * a compact, URL-safe token.
   *
   * @param byteLength - Number of random bytes to encode.
   */
  public randomBase64Url(byteLength: number): string {
    assertLength(byteLength, 'byteLength');
    return base64UrlEncode(this.draw(byteLength));
  }

  // --- UUIDs ---------------------------------------------------------------

  /**
   * Return a random UUID — an alias for {@link uuidV4}, the default choice when
   * you just want "a UUID".
   */
  public uuid(): string {
    return this.uuidV4();
  }

  /**
   * Return a random **UUIDv4** (RFC 9562 §5.4): 122 random bits with the version
   * and variant fields set.
   */
  public uuidV4(): string {
    const bytes = this.draw(16);
    bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40; // version 4
    bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80; // variant 10xx
    return formatUuid(bytes);
  }

  /**
   * Return a time-ordered **UUIDv7** (RFC 9562 §5.7): a 48-bit Unix-millisecond
   * timestamp followed by 74 random bits, so identifiers sort by creation time
   * while staying unguessable.
   *
   * @param options - {@link UuidV7Options}; the embedded time comes from the
   *   provided clock, otherwise the generator's clock.
   */
  public uuidV7(options: UuidV7Options = {}): string {
    const clock = options.clock ?? this.clock;
    const millis = Math.floor(clock());
    if (!Number.isFinite(millis) || millis < 0) {
      throw new InvalidArgumentError('clock must return a finite, non-negative epoch-millisecond value', {
        context: { millis: String(millis) },
      });
    }
    const bytes = this.draw(16);
    const timestamp = BigInt(millis) & ((1n << 48n) - 1n);
    for (let i = 0; i < 6; i++) {
      // Big-endian: byte 0 holds the most-significant 8 bits of the 48-bit stamp.
      bytes[i] = Number((timestamp >> BigInt((5 - i) * 8)) & 0xffn);
    }
    bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x70; // version 7
    bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80; // variant 10xx
    return formatUuid(bytes);
  }

  // --- Collections ---------------------------------------------------------

  /**
   * Return one uniformly chosen element of `items`.
   *
   * @param items - A non-empty array to choose from.
   * @throws {EmptyRangeError} If `items` is empty.
   */
  public choice<T>(items: readonly T[]): T {
    if (items.length === 0) {
      throw new EmptyRangeError('cannot choose from an empty collection');
    }
    return items[this.randomBelow(items.length)] as T;
  }

  /**
   * Return `count` elements sampled **without replacement**, uniformly at random.
   *
   * Uses a partial Fisher–Yates shuffle, so it is `O(count)` extra work and never
   * returns the same position twice.
   *
   * @param items - The population to sample from.
   * @param count - How many distinct elements to draw (`0 … items.length`).
   */
  public sample<T>(items: readonly T[], count: number): T[] {
    assertLength(count, 'count');
    if (count > items.length) {
      throw new InvalidArgumentError('count cannot exceed the population size', {
        context: { count, population: items.length },
      });
    }
    const pool = items.slice();
    const result = new Array<T>(count);
    for (let i = 0; i < count; i++) {
      const j = i + this.randomBelow(pool.length - i);
      const a = pool[i] as T;
      const b = pool[j] as T;
      pool[i] = b;
      pool[j] = a;
      result[i] = pool[i] as T;
    }
    return result;
  }

  /**
   * Return a new array holding an unbiased permutation of `items` (Fisher–Yates).
   *
   * @param items - The elements to shuffle; the input is not modified.
   */
  public shuffle<T>(items: readonly T[]): T[] {
    const copy = items.slice();
    this.shuffleInPlace(copy);
    return copy;
  }

  /**
   * Shuffle `items` in place with an unbiased Fisher–Yates permutation.
   *
   * @param items - The array to shuffle; mutated and returned for chaining.
   */
  public shuffleInPlace<T>(items: T[]): T[] {
    for (let i = items.length - 1; i > 0; i--) {
      const j = this.randomBelow(i + 1);
      const a = items[i] as T;
      const b = items[j] as T;
      items[i] = b;
      items[j] = a;
    }
    return items;
  }

  // --- Lifecycle -----------------------------------------------------------

  /**
   * Force an immediate reseed with fresh entropy from the configured source.
   *
   * Rarely necessary — the generator reseeds itself at the reseed interval — but
   * useful to inject freshly gathered entropy at a security boundary (e.g. just
   * after a fork, or when extra `additionalInput` is available).
   *
   * @param additionalInput - Optional extra bytes/string to fold into the reseed.
   * @throws {InvalidArgumentError} If the generator is in deterministic mode.
   */
  public reseed(additionalInput?: Uint8Array | string): void {
    this.ensureLive();
    if (this.deterministic) {
      throw new InvalidArgumentError('a deterministic (seeded) generator cannot be reseeded');
    }
    this.performReseed(toBytes(additionalInput));
  }

  /** Return a non-sensitive snapshot of the generator's state, for logging/metrics. */
  public stats(): GeneratorStats {
    return {
      strength: this.strength,
      entropySource: this.entropySourceName,
      deterministic: this.deterministic,
      reseedCounter: this.drbg.reseedCounter,
      reseeds: this.reseeds,
      bytesGenerated: this.bytesGenerated,
      reseedInterval: this.reseedInterval,
      destroyed: this.destroyed,
    };
  }

  /**
   * Wipe the generator's secret state. Subsequent calls throw. Idempotent.
   */
  public destroy(): void {
    if (!this.destroyed) {
      this.drbg.destroy();
      this.destroyed = true;
    }
  }

  // --- Internals -----------------------------------------------------------

  /**
   * The single choke point for output: enforce liveness and the reseed policy,
   * then squeeze from the DRBG and account for the bytes produced.
   */
  private draw(length: number): Uint8Array {
    this.ensureLive();
    if (this.drbg.needsReseed()) {
      if (this.autoReseed) {
        this.performReseed(EMPTY);
      } else {
        throw new GeneratorStateError(
          'reseed interval reached and automatic reseeding is disabled; call reseed()',
          ErrorCode.RESEED_REQUIRED,
        );
      }
    }
    const output = this.drbg.generate(length);
    this.bytesGenerated += length;
    return output;
  }

  /** Uniform `BigInt` in `[0, maxExclusive)` via masked rejection sampling. */
  private uniformBigInt(maxExclusive: bigint): bigint {
    if (maxExclusive <= 0n) {
      throw new EmptyRangeError('maxExclusive must be greater than 0');
    }
    if (maxExclusive === 1n) {
      return 0n;
    }
    // Bit-length of the largest valid value; masking to it keeps the rejection
    // probability below 1/2, so the loop terminates in < 2 iterations on average.
    const bitLength = (maxExclusive - 1n).toString(2).length;
    const byteLength = Math.ceil(bitLength / 8);
    const mask = (1n << BigInt(bitLength)) - 1n;
    for (;;) {
      const candidate = bytesToBigIntBE(this.draw(byteLength)) & mask;
      if (candidate < maxExclusive) {
        return candidate;
      }
    }
  }

  /** Gather (or derive) the entropy + nonce used to instantiate the DRBG. */
  private gatherInstantiationSeed(seed: Uint8Array | undefined): { entropy: Uint8Array; nonce: Uint8Array } {
    if (seed !== undefined) {
      if (!(seed instanceof Uint8Array) || seed.length === 0) {
        throw new InvalidSeedError('a deterministic seed must be a non-empty Uint8Array', {
          context: { length: seed instanceof Uint8Array ? seed.length : -1 },
        });
      }
      // Copy so we can wipe our working buffer without touching the caller's.
      return { entropy: copyBytes(seed), nonce: EMPTY };
    }
    return {
      entropy: this.entropySource.gather(this.profile.entropyBytes),
      // The nonce is always OS-drawn: independent of the (possibly custom) source.
      nonce: systemEntropySource.gather(this.profile.nonceBytes),
    };
  }

  /** Shared reseed path used by both explicit {@link reseed} and auto-reseed. */
  private performReseed(additionalInput: Uint8Array): void {
    const entropy = this.entropySource.gather(this.profile.entropyBytes);
    try {
      this.drbg.reseed(entropy, additionalInput);
    } finally {
      wipe(entropy);
    }
    this.reseeds += 1;
  }

  /** Guard every public operation against use-after-destroy. */
  private ensureLive(): void {
    if (this.destroyed) {
      throw new GeneratorStateError('generator has been destroyed', ErrorCode.GENERATOR_DESTROYED);
    }
  }
}

/** Format 16 bytes as a canonical `8-4-4-4-12` UUID string. */
function formatUuid(bytes: Uint8Array): string {
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
