/**
 * @packageDocumentation
 * The security-strength registry: the single source of truth for how the
 * generator is sized at each supported strength.
 *
 * ## One core, three strengths
 *
 * Every strength shares the **same** SHAKE256 DRBG core and the same 512-bit
 * working-state width ({@link SEEDLEN}) — SHAKE256 already provides 256-bit
 * security, so the primitive never needs to change. What the strength selects is
 * the *seeding policy*:
 *
 * - how many bytes of entropy and nonce are drawn to instantiate/reseed
 *   (NIST SP 800-90A §8.6.7 requires at least `security_strength` bits of
 *   entropy, plus a nonce of at least `security_strength / 2` bits), and
 * - which **ML-KEM** parameter set the default, lattice-conditioned entropy
 *   source uses (§ see `entropy.ts`).
 *
 * This mirrors how a post-quantum signature library exposes several parameter
 * sets: same idea, calibrated work factors.
 */

import { UnsupportedStrengthError } from '../errors.js';

/**
 * The DRBG working-state width in bytes (512 bits).
 *
 * NIST SP 800-90A's Hash_DRBG uses a `seedlen`-bit state (440 bits for SHA-256).
 * We use a generous 512-bit state so that, combined with SHAKE256's 256-bit
 * capacity, there is a wide margin against both classical collision search and
 * Grover-accelerated quantum search. It is intentionally the same for every
 * strength — only the *input* entropy scales.
 */
export const SEEDLEN = 64;

/**
 * Supported target security strengths, in bits, benchmarked against the cost of
 * a generic attack on a symmetric primitive of that strength.
 *
 * These line up with the NIST post-quantum security categories used by ML-KEM /
 * ML-DSA: 128 ≈ category 1/2, 192 ≈ category 3, 256 ≈ category 5.
 */
export type SecurityStrength = 128 | 192 | 256;

/**
 * The recommended default strength.
 *
 * Randomness is cheap and long-lived (a key generated today may guard data for
 * decades), so we default to the **maximum** 256-bit strength. The only cost is
 * a few extra seed bytes and the larger ML-KEM parameter set at reseed time,
 * both negligible next to the value of the secrets a CSPRNG protects.
 */
export const DEFAULT_SECURITY_STRENGTH: SecurityStrength = 256;

/** The ML-KEM parameter set names usable for lattice entropy conditioning. */
export type MlKemName = 'ML-KEM-512' | 'ML-KEM-768' | 'ML-KEM-1024';

/** Immutable seeding policy for one security strength. */
export interface StrengthProfile {
  /** Target security strength in bits. */
  readonly strength: SecurityStrength;
  /**
   * Bytes of entropy drawn from the source per (re)seed. At least
   * `strength / 8` bytes, i.e. `strength` bits (SP 800-90A §8.6.3).
   */
  readonly entropyBytes: number;
  /**
   * Bytes of nonce drawn per instantiation. At least `strength / 16` bytes, i.e.
   * `strength / 2` bits (SP 800-90A §8.6.7).
   */
  readonly nonceBytes: number;
  /**
   * Maximum number of `generate` calls between reseeds. Well within SP 800-90A's
   * `2^48` ceiling; kept modest so that automatic reseeding refreshes forward
   * secrecy frequently.
   */
  readonly reseedInterval: number;
  /** ML-KEM parameter set used by the default lattice-conditioned entropy source. */
  readonly mlKem: MlKemName;
}

/**
 * Registry of the seeding policy for every supported strength.
 *
 * `entropyBytes` and `nonceBytes` satisfy the SP 800-90A minimums with the exact
 * `security_strength` and `security_strength / 2` bit counts, and the ML-KEM set
 * is matched to the same category so the lattice stage is never the weak link.
 */
export const SECURITY_STRENGTHS: Readonly<Record<SecurityStrength, StrengthProfile>> = {
  128: {
    strength: 128,
    entropyBytes: 16,
    nonceBytes: 8,
    reseedInterval: 1 << 20,
    mlKem: 'ML-KEM-512',
  },
  192: {
    strength: 192,
    entropyBytes: 24,
    nonceBytes: 12,
    reseedInterval: 1 << 20,
    mlKem: 'ML-KEM-768',
  },
  256: {
    strength: 256,
    entropyBytes: 32,
    nonceBytes: 16,
    reseedInterval: 1 << 20,
    mlKem: 'ML-KEM-1024',
  },
};

/** Every supported strength, handy for iteration and validation. */
export const SUPPORTED_STRENGTHS: readonly SecurityStrength[] = Object.freeze([128, 192, 256]);

/** Type guard: is `value` one of the supported security strengths? */
export function isSecurityStrength(value: unknown): value is SecurityStrength {
  return value === 128 || value === 192 || value === 256;
}

/**
 * Look up the seeding profile for a strength, validating the input.
 *
 * @param strength - The requested strength in bits.
 * @returns The immutable {@link StrengthProfile}.
 * @throws {UnsupportedStrengthError} If `strength` is not 128, 192, or 256.
 */
export function getStrengthProfile(strength: SecurityStrength): StrengthProfile {
  if (!isSecurityStrength(strength)) {
    throw new UnsupportedStrengthError(`unsupported security strength: ${String(strength)}`, {
      context: { strength: String(strength), supported: SUPPORTED_STRENGTHS.join(', ') },
    });
  }
  return SECURITY_STRENGTHS[strength];
}
