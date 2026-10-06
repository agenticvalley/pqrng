/**
 * @packageDocumentation
 * Byte helpers.
 *
 * A thin, centralized seam over the low-level primitives shipped by the audited
 * cryptography dependencies, plus the handful of big-endian integer routines the
 * DRBG needs to update its internal state (NIST SP 800-90A performs its state
 * update as addition modulo `2^seedlen`, which we implement here once).
 *
 * Keeping these here makes it trivial to swap an implementation without touching
 * call sites, and gives every consumer one obvious place to find "how do I get
 * secure random bytes / turn bytes into an integer / add two state words".
 */

import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils';

export { concatBytes, randomBytes, utf8ToBytes };

/**
 * Read a big-endian unsigned 32-bit integer from `bytes` at `offset`.
 *
 * @param bytes - Source buffer; must hold at least four bytes from `offset`.
 * @param offset - Byte offset to read from (defaults to 0).
 * @returns The value as an unsigned 32-bit number (`0 … 2^32 − 1`).
 */
export function readUint32BE(bytes: Uint8Array, offset = 0): number {
  const b0 = bytes[offset] ?? 0;
  const b1 = bytes[offset + 1] ?? 0;
  const b2 = bytes[offset + 2] ?? 0;
  const b3 = bytes[offset + 3] ?? 0;
  // `>>> 0` coerces the result back to an unsigned 32-bit integer.
  return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
}

/**
 * Interpret a byte array as a big-endian non-negative integer.
 *
 * @param bytes - The big-endian bytes (most-significant byte first).
 * @returns The value as a {@link BigInt}.
 */
export function bytesToBigIntBE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

/**
 * Encode a non-negative integer as a fixed-length big-endian byte array,
 * truncating to the low `length` bytes (i.e. reducing modulo `2^(8·length)`).
 *
 * @param value - The non-negative integer to encode.
 * @param length - The exact output length in bytes.
 * @returns A `length`-byte big-endian encoding of `value mod 2^(8·length)`.
 */
export function bigIntToBytesBE(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let remaining = value & ((1n << BigInt(length * 8)) - 1n);
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

/**
 * Add several big-endian words together modulo `2^(8·base.length)`.
 *
 * This is the modular addition NIST SP 800-90A uses to fold new material into
 * the DRBG working state `V` (§10.1.1). Every addend is reduced into the width
 * of `base`, so the result is always exactly `base.length` bytes.
 *
 * @param base - The word whose width defines the modulus.
 * @param addends - Further words (bytes) or small counters (bigint) to add in.
 * @returns `base + Σ addends (mod 2^(8·base.length))` as fresh bytes.
 */
export function addModPow2(base: Uint8Array, ...addends: readonly (Uint8Array | bigint)[]): Uint8Array {
  let sum = bytesToBigIntBE(base);
  for (const addend of addends) {
    sum += typeof addend === 'bigint' ? addend : bytesToBigIntBE(addend);
  }
  return bigIntToBytesBE(sum, base.length);
}

/** Create a defensive copy of a byte array. */
export function copyBytes(bytes: Uint8Array): Uint8Array {
  return bytes.slice();
}

/**
 * Best-effort zeroization of sensitive bytes.
 *
 * Overwrites the buffer in place so a discarded seed or DRBG state word does not
 * linger in memory any longer than necessary. In a managed runtime this cannot
 * be guaranteed (the GC may already have copied the value), but wiping what we
 * can is strictly better than leaving key material behind.
 *
 * @param buffers - One or more buffers to overwrite with zeros.
 */
export function wipe(...buffers: readonly Uint8Array[]): void {
  for (const buffer of buffers) {
    buffer.fill(0);
  }
}
