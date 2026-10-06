/**
 * @packageDocumentation
 * Entropy sources.
 *
 * A DRBG is only as unpredictable as the seed it is given, so this module owns
 * the question "where do fresh seed bytes come from?". An {@link EntropySource}
 * is a tiny interface — "give me at least N high-entropy bytes" — with two
 * built-in implementations:
 *
 * 1. {@link systemEntropySource} — the operating-system CSPRNG
 *    (`crypto.getRandomValues`), the entropy **source of record** on every
 *    platform.
 * 2. {@link latticeConditionedEntropySource} — the same OS entropy passed
 *    through an **ML-KEM** (FIPS-203) lattice operation and then conditioned with
 *    SHAKE256. This is the default, and the reason the generator's *entire*
 *    cryptographic pipeline — conditioning, expansion, and output — is
 *    post-quantum.
 *
 * ### An honest note on the lattice stage
 *
 * ML-KEM key generation and encapsulation are themselves seeded by the OS
 * CSPRNG, so the lattice stage does **not** conjure entropy that the OS did not
 * already provide; no algorithm can. What it *does* provide is defense-in-depth:
 * the final seed is SHAKE256 over **two independent OS draws** (a direct one and
 * the draws consumed inside ML-KEM) plus the lattice-structured shared secret and
 * ciphertext. A subtle bias in any single draw is diffused, and every byte that
 * reaches the DRBG has passed exclusively through post-quantum primitives.
 */

import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { EntropySourceError } from '../errors.js';
import { randomBytes, utf8ToBytes, wipe } from '../utils/bytes.js';
import type { MlKemName, SecurityStrength } from './strength.js';
import { getStrengthProfile } from './strength.js';
import { shake256Xof } from './xof.js';

/**
 * A pluggable source of seed entropy for the DRBG.
 *
 * Implementations must return **at least** `minBytes` bytes of high-entropy
 * material; returning more is permitted (the DRBG conditions whatever it gets).
 */
export interface EntropySource {
  /** Human-readable identifier, surfaced in {@link GeneratorStats.entropySource}. */
  readonly name: string;
  /**
   * Produce at least `minBytes` bytes of entropy.
   *
   * @param minBytes - The minimum number of bytes required.
   * @returns Entropy bytes (length ≥ `minBytes`).
   * @throws {EntropySourceError} If the underlying source fails or under-delivers.
   */
  gather(minBytes: number): Uint8Array;
}

/** Minimal structural view of the ML-KEM primitives we consume. */
interface Kem {
  keygen(seed?: Uint8Array): { publicKey: Uint8Array; secretKey: Uint8Array };
  encapsulate(publicKey: Uint8Array, msg?: Uint8Array): { cipherText: Uint8Array; sharedSecret: Uint8Array };
}

/** Maps each ML-KEM parameter-set name to its concrete implementation. */
const ML_KEMS: Readonly<Record<MlKemName, Kem>> = {
  'ML-KEM-512': ml_kem512,
  'ML-KEM-768': ml_kem768,
  'ML-KEM-1024': ml_kem1024,
};

/** Domain-separation label for the entropy-conditioning SHAKE256 call. */
const CONDITION_LABEL = utf8ToBytes('pqrng/entropy-conditioning/v1');

/**
 * The operating-system CSPRNG as an entropy source.
 *
 * Backed by `crypto.getRandomValues` (via the audited `@noble/hashes` helper),
 * which draws from the platform's cryptographic RNG. This is the raw entropy
 * every other source ultimately builds on.
 */
export const systemEntropySource: EntropySource = {
  name: 'system-csprng',
  gather(minBytes: number): Uint8Array {
    const bytes = randomBytes(minBytes);
    if (bytes.length < minBytes) {
      throw new EntropySourceError('system CSPRNG returned too few bytes', {
        context: { requested: minBytes, received: bytes.length },
      });
    }
    return bytes;
  },
};

/**
 * Build an entropy source that conditions OS entropy through an ML-KEM lattice
 * operation.
 *
 * Each `gather` draws fresh OS entropy, generates an ephemeral ML-KEM key pair,
 * encapsulates to it, and folds the OS bytes together with the lattice-derived
 * shared secret and ciphertext through SHAKE256. Ephemeral secret material is
 * wiped before returning.
 *
 * @param mlKem - The ML-KEM parameter set to use.
 * @returns An {@link EntropySource} whose output has passed only through
 *   post-quantum primitives.
 */
export function latticeConditionedEntropySource(mlKem: MlKemName): EntropySource {
  const kem = ML_KEMS[mlKem];
  return {
    name: `lattice-conditioned(${mlKem})`,
    gather(minBytes: number): Uint8Array {
      // 1. A direct OS draw — the entropy of record.
      const systemBytes = systemEntropySource.gather(minBytes);
      // 2. A lattice pass over independent OS draws (keygen + encapsulate seed
      //    themselves from the OS CSPRNG internally).
      const { publicKey, secretKey } = kem.keygen();
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey);
      try {
        // 3. Condition everything down to the requested width with SHAKE256.
        return shake256Xof(minBytes, CONDITION_LABEL, systemBytes, sharedSecret, cipherText);
      } finally {
        // Ephemeral KEM secrets have served their purpose; do not let them linger.
        wipe(secretKey, sharedSecret, systemBytes);
      }
    },
  };
}

/**
 * The default entropy source for a given strength: OS entropy conditioned
 * through the strength's matched ML-KEM parameter set.
 *
 * @param strength - The target security strength.
 * @returns The default lattice-conditioned {@link EntropySource}.
 */
export function defaultEntropySource(strength: SecurityStrength): EntropySource {
  return latticeConditionedEntropySource(getStrengthProfile(strength).mlKem);
}
