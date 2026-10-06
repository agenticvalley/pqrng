/**
 * @packageDocumentation
 * The public data model: the option and statistics shapes that flow across the
 * library's surface. Runtime logic lives elsewhere; this module is types only,
 * so it is safe to import from anywhere without pulling in code.
 */

import type { EntropySource } from './crypto/entropy.js';
import type { SecurityStrength } from './crypto/strength.js';
import type { Clock } from './utils/time.js';

/**
 * Options for constructing a {@link PostQuantumRandom} generator.
 *
 * Every field is optional; the defaults produce a 256-bit-strength, lattice
 * entropy-conditioned, auto-reseeding generator suitable for general use.
 */
export interface GeneratorOptions {
  /**
   * Target security strength in bits. Selects the entropy-input size, the
   * automatic reseed interval, and (for the default entropy source) the ML-KEM
   * parameter set used to condition entropy. Defaults to `256`.
   */
  readonly strength?: SecurityStrength;

  /**
   * The entropy source that seeds and reseeds the DRBG. Defaults to a
   * {@link EntropySource} that conditions the operating-system CSPRNG through an
   * ML-KEM lattice operation. Pass a system-only source to opt out of the
   * lattice stage, or a custom source to integrate a hardware RNG.
   */
  readonly entropySource?: EntropySource;

  /**
   * Optional personalization string (NIST SP 800-90A §8.7.1): caller-supplied
   * bytes mixed into the initial seed so that two generators instantiated from
   * the same entropy but different personalization diverge. Has no effect on
   * security but is good hygiene for per-tenant / per-purpose separation.
   */
  readonly personalization?: Uint8Array | string;

  /**
   * A fixed seed for **deterministic** operation.
   *
   * When present, the generator is seeded from exactly these bytes instead of
   * the entropy source, producing a fully reproducible stream. This is intended
   * for tests, simulations, and reproducible sampling — **never** for values
   * that must be unpredictable. Providing a seed also disables automatic
   * reseeding (a reseed would break reproducibility).
   */
  readonly seed?: Uint8Array;

  /**
   * Number of `generate` calls permitted between reseeds before the reseed
   * interval is considered reached. Defaults to the strength profile's value.
   */
  readonly reseedInterval?: number;

  /**
   * Whether the generator silently pulls fresh entropy and reseeds when the
   * reseed interval is reached. Defaults to `true` (and is forced to `false` in
   * deterministic/seeded mode). When `false`, hitting the interval raises a
   * {@link GeneratorStateError} until {@link PostQuantumRandom.reseed} is called.
   */
  readonly autoReseed?: boolean;

  /** Millisecond clock used by time-based helpers such as UUIDv7. Defaults to `Date.now`. */
  readonly clock?: Clock;
}

/** A non-sensitive snapshot of a generator's operating state, for logging and metrics. */
export interface GeneratorStats {
  /** The configured security strength in bits. */
  readonly strength: SecurityStrength;
  /** Human-readable name of the active entropy source. */
  readonly entropySource: string;
  /** Whether the generator is running in deterministic (fixed-seed) mode. */
  readonly deterministic: boolean;
  /** `generate` calls since the most recent (re)seed. */
  readonly reseedCounter: number;
  /** Total number of reseeds performed since instantiation. */
  readonly reseeds: number;
  /** Total number of random bytes produced since instantiation. */
  readonly bytesGenerated: number;
  /** The reseed interval in effect. */
  readonly reseedInterval: number;
  /** Whether the generator has been destroyed. */
  readonly destroyed: boolean;
}

/** Options for {@link PostQuantumRandom.randomString}. */
export interface RandomStringOptions {
  /**
   * The alphabet to draw characters from. Each character is chosen uniformly and
   * without modulo bias. Defaults to the 64-character URL-safe base64url
   * alphabet. See {@link Alphabets} for ready-made choices.
   */
  readonly alphabet?: string;
}

/** Options for the time-ordered {@link PostQuantumRandom.uuidV7} generator. */
export interface UuidV7Options {
  /** Millisecond clock supplying the embedded timestamp. Defaults to the generator's clock. */
  readonly clock?: Clock;
}
