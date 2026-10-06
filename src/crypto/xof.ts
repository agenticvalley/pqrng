/**
 * @packageDocumentation
 * The **only** module that talks directly to the concrete Keccak primitive.
 *
 * The entire generator is built on **SHAKE256**, the extendable-output function
 * (XOF) standardized in NIST **FIPS-202** and, not coincidentally, the exact
 * symmetric primitive that the post-quantum standards **ML-KEM** (FIPS-203) and
 * **ML-DSA** (FIPS-204) use internally for all of their hashing and expansion.
 * Basing the DRBG on the same sponge is what makes this a *post-quantum* RNG:
 *
 * - A XOF is the natural fit for a DRBG — "absorb a seed, squeeze arbitrarily
 *   many output bytes" is precisely the SP 800-90A generate operation, with no
 *   awkward counter/`Hash_df` loop needed.
 * - SHAKE256 targets **256-bit** classical security. Grover's algorithm only
 *   square-roots the cost of a generic search, so even against a large quantum
 *   computer the effective preimage strength stays around **128 bits** — a
 *   comfortable margin. Contrast a naive AES-128-CTR-DRBG, where Grover erodes
 *   the key search to roughly 64 bits.
 *
 * Every hash/squeeze in the library funnels through the two helpers here so the
 * choice of primitive lives in exactly one place.
 */

import { shake256 } from '@noble/hashes/sha3';
import { concatBytes } from '../utils/bytes.js';

/**
 * Absorb `inputs` and squeeze exactly `outputLength` bytes from SHAKE256.
 *
 * Because SHAKE256 is a XOF, `outputLength` may be any non-negative size; the
 * sponge produces a stream and we take the requested prefix. The inputs are
 * concatenated in order before absorption, so callers get deterministic,
 * order-sensitive domain separation simply by choosing what they pass.
 *
 * @param outputLength - Number of output bytes to squeeze.
 * @param inputs - Byte segments to absorb, in order.
 * @returns Exactly `outputLength` bytes of SHAKE256 output.
 */
export function shake256Xof(outputLength: number, ...inputs: readonly Uint8Array[]): Uint8Array {
  return shake256(inputs.length === 1 ? inputs[0]! : concatBytes(...inputs), {
    dkLen: outputLength,
  });
}
