/**
 * @packageDocumentation
 * # @agenticvalley/pqrng
 *
 * **A post-quantum-only cryptographically secure random number generator.** The
 * ergonomic `random*` surface you already reach for — bytes, integers, ranges,
 * floats, booleans, tokens, UUIDs, `choice` / `sample` / `shuffle` — but every
 * output byte is produced by a **reseedable NIST SP 800-90A DRBG built on the
 * SHAKE256 sponge (FIPS-202)**, with entropy conditioned through an **ML-KEM
 * (FIPS-203)** lattice stage.
 *
 * There is **no AES-CTR-DRBG, no truncated-hash DRBG, and no classical fallback**:
 * the entire pipeline — entropy conditioning, state update, and output — runs
 * exclusively on primitives that keep a wide security margin against a
 * large-scale quantum computer.
 *
 * ## Why "post-quantum" for randomness?
 *
 * A DRBG's unpredictability rests on its internal primitive. Grover's algorithm
 * gives a quantum attacker a quadratic speedup on generic search, which halves
 * the effective bit-strength of a symmetric primitive:
 *
 * - AES-128-CTR-DRBG → ~64-bit quantum margin (uncomfortable).
 * - SHAKE256 DRBG with a 512-bit state → ~128-bit quantum margin (comfortable).
 *
 * SHAKE256 is also exactly the sponge that ML-KEM and ML-DSA are built on, so
 * this generator shares its cryptographic foundations with the NIST post-quantum
 * standards rather than bolting on a separate one.
 *
 * ## How a value is produced
 *
 * ```text
 *   OS CSPRNG  ─┐
 *               ├─▶ ML-KEM encapsulation ─▶ SHAKE256 conditioning ─▶ seed
 *   OS CSPRNG  ─┘        (lattice)                (FIPS-202)          │
 *                                                                    ▼
 *                                     SHAKE256 Hash_DRBG  ◀──────────┘
 *                                     (SP 800-90A state machine)
 *                                                 │
 *                                                 ▼
 *                            uniform bytes ─▶ unbiased integers / floats /
 *                                             strings / UUIDs / shuffles
 * ```
 *
 * The operating-system CSPRNG remains the raw entropy source of record; the
 * post-quantum primitives own every *cryptographic* step from conditioning to
 * output.
 *
 * @example Zero-setup facade
 * ```ts
 * import { randomInt, randomString, uuidV4, shuffle } from '@agenticvalley/pqrng';
 *
 * randomInt(1, 7);              // a fair d6: an integer in 1..6
 * randomString(21);            // a URL-safe token, e.g. "Xa3…"
 * uuidV4();                    // an RFC 9562 UUIDv4
 * shuffle(['a', 'b', 'c']);    // an unbiased permutation
 * ```
 *
 * @example A configured instance
 * ```ts
 * import { createGenerator } from '@agenticvalley/pqrng';
 *
 * const rng = createGenerator({ strength: 192 });
 * const key = rng.randomBytes(32);
 * const otp = rng.randomString(6, { alphabet: '0123456789' });
 * ```
 *
 * @example Reproducible (deterministic) mode — for tests only
 * ```ts
 * import { createGenerator } from '@agenticvalley/pqrng';
 *
 * const seed = new TextEncoder().encode('fixed-test-seed');
 * const a = createGenerator({ seed });
 * const b = createGenerator({ seed });
 * a.randomBytes(16); // identical to…
 * b.randomBytes(16); // …this — never use a fixed seed for real secrets.
 * ```
 */

import {
  choice,
  createGenerator,
  getDefaultGenerator,
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
  uuid,
  uuidV4,
  uuidV7,
} from './facade.js';

// --- Zero-setup facade (backed by a shared default generator) ---------------
export {
  getDefaultGenerator,
  createGenerator,
  randomBytes,
  randomUint32,
  randomBelow,
  randomInt,
  randomIntInclusive,
  randomBigInt,
  randomBigIntInRange,
  randomFloat,
  randomBoolean,
  randomString,
  randomHex,
  randomBase64Url,
  uuid,
  uuidV4,
  uuidV7,
  choice,
  sample,
  shuffle,
  reseed,
  stats,
} from './facade.js';

// --- The generator class + alphabets ----------------------------------------
export { PostQuantumRandom, Alphabets } from './generator.js';

// --- Data model -------------------------------------------------------------
export type { GeneratorOptions, GeneratorStats, RandomStringOptions, UuidV7Options } from './types.js';

// --- Security-strength registry ---------------------------------------------
export {
  SEEDLEN,
  DEFAULT_SECURITY_STRENGTH,
  SECURITY_STRENGTHS,
  SUPPORTED_STRENGTHS,
  getStrengthProfile,
  isSecurityStrength,
  type SecurityStrength,
  type StrengthProfile,
  type MlKemName,
} from './crypto/strength.js';

// --- Entropy sources + low-level DRBG (advanced callers) --------------------
export {
  systemEntropySource,
  latticeConditionedEntropySource,
  defaultEntropySource,
  type EntropySource,
} from './crypto/entropy.js';
export { ShakeDrbg, type DrbgSeed } from './crypto/drbg.js';
export { shake256Xof } from './crypto/xof.js';

// --- Errors -----------------------------------------------------------------
export {
  ErrorCode,
  PqRngError,
  InvalidArgumentError,
  EmptyRangeError,
  UnsupportedStrengthError,
  InvalidSeedError,
  EntropySourceError,
  GeneratorStateError,
  type ErrorContext,
  type PqRngErrorOptions,
} from './errors.js';

// --- Selected utilities -----------------------------------------------------
export { base64UrlEncode, base64UrlDecode, bytesToHex, hexToBytes } from './utils/encoding.js';
export type { Clock } from './utils/time.js';

// --- Default (namespace) export ---------------------------------------------
/**
 * Everything bundled as one object, so you can `import pqrng from
 * '@agenticvalley/pqrng'` and call `pqrng.randomInt(...)`, `pqrng.uuidV4(...)`,
 * `pqrng.createGenerator(...)`, and so on — no named imports required.
 */
const pqrng = {
  createGenerator,
  getDefaultGenerator,
  randomBytes,
  randomUint32,
  randomBelow,
  randomInt,
  randomIntInclusive,
  randomBigInt,
  randomBigIntInRange,
  randomFloat,
  randomBoolean,
  randomString,
  randomHex,
  randomBase64Url,
  uuid,
  uuidV4,
  uuidV7,
  choice,
  sample,
  shuffle,
  reseed,
  stats,
};

export default pqrng;
