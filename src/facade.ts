/**
 * @packageDocumentation
 * The package-level facade.
 *
 * For the common case — "just give me a good random value" — importing a class
 * and constructing it is friction. This module exposes every generator method as
 * a free function backed by a single, lazily-created, process-wide
 * {@link PostQuantumRandom} instance, so `randomInt(1, 7)` works with no setup.
 *
 * The shared instance uses the default configuration (256-bit strength, lattice
 * entropy conditioning, auto-reseed). When you need bespoke settings — a fixed
 * seed, a custom entropy source, a different strength — call
 * {@link createGenerator} and keep your own instance.
 */

import { PostQuantumRandom } from './generator.js';
import type { GeneratorOptions, GeneratorStats, RandomStringOptions, UuidV7Options } from './types.js';

/** The lazily-instantiated, process-wide default generator. */
let sharedGenerator: PostQuantumRandom | undefined;

/** Return (creating on first use) the shared default generator. */
export function getDefaultGenerator(): PostQuantumRandom {
  sharedGenerator ??= new PostQuantumRandom();
  return sharedGenerator;
}

/**
 * Create a new, independent generator with custom options.
 *
 * @param options - {@link GeneratorOptions}.
 */
export function createGenerator(options?: GeneratorOptions): PostQuantumRandom {
  return new PostQuantumRandom(options);
}

/** Return `length` fresh pseudorandom bytes from the shared generator. */
export function randomBytes(length: number): Uint8Array {
  return getDefaultGenerator().randomBytes(length);
}

/** Return a uniform unsigned 32-bit integer from the shared generator. */
export function randomUint32(): number {
  return getDefaultGenerator().randomUint32();
}

/** Return a uniform integer in `[0, maxExclusive)` from the shared generator. */
export function randomBelow(maxExclusive: number): number {
  return getDefaultGenerator().randomBelow(maxExclusive);
}

/** Return a uniform integer in `[minInclusive, maxExclusive)` from the shared generator. */
export function randomInt(minInclusive: number, maxExclusive: number): number {
  return getDefaultGenerator().randomInt(minInclusive, maxExclusive);
}

/** Return a uniform integer in `[min, max]` (inclusive) from the shared generator. */
export function randomIntInclusive(min: number, max: number): number {
  return getDefaultGenerator().randomIntInclusive(min, max);
}

/** Return a uniform `bigint` in `[0, maxExclusive)` from the shared generator. */
export function randomBigInt(maxExclusive: bigint): bigint {
  return getDefaultGenerator().randomBigInt(maxExclusive);
}

/** Return a uniform `bigint` in `[minInclusive, maxExclusive)` from the shared generator. */
export function randomBigIntInRange(minInclusive: bigint, maxExclusive: bigint): bigint {
  return getDefaultGenerator().randomBigIntInRange(minInclusive, maxExclusive);
}

/** Return a uniform double in `[0, 1)` from the shared generator. */
export function randomFloat(): number {
  return getDefaultGenerator().randomFloat();
}

/** Return a random boolean (defaulting to a fair coin) from the shared generator. */
export function randomBoolean(probability?: number): boolean {
  return getDefaultGenerator().randomBoolean(probability);
}

/** Return a random string of `length` characters from the shared generator. */
export function randomString(length: number, options?: RandomStringOptions): string {
  return getDefaultGenerator().randomString(length, options);
}

/** Return `byteLength` random bytes as lowercase hex from the shared generator. */
export function randomHex(byteLength: number): string {
  return getDefaultGenerator().randomHex(byteLength);
}

/** Return `byteLength` random bytes as unpadded base64url from the shared generator. */
export function randomBase64Url(byteLength: number): string {
  return getDefaultGenerator().randomBase64Url(byteLength);
}

/** Return a random UUID (v4) from the shared generator. */
export function uuid(): string {
  return getDefaultGenerator().uuid();
}

/** Return a random UUIDv4 from the shared generator. */
export function uuidV4(): string {
  return getDefaultGenerator().uuidV4();
}

/** Return a time-ordered UUIDv7 from the shared generator. */
export function uuidV7(options?: UuidV7Options): string {
  return getDefaultGenerator().uuidV7(options);
}

/** Return one uniformly chosen element of `items` from the shared generator. */
export function choice<T>(items: readonly T[]): T {
  return getDefaultGenerator().choice(items);
}

/** Sample `count` elements without replacement from the shared generator. */
export function sample<T>(items: readonly T[], count: number): T[] {
  return getDefaultGenerator().sample(items, count);
}

/** Return an unbiased permutation of `items` from the shared generator. */
export function shuffle<T>(items: readonly T[]): T[] {
  return getDefaultGenerator().shuffle(items);
}

/** Force a reseed of the shared generator with fresh entropy. */
export function reseed(additionalInput?: Uint8Array | string): void {
  getDefaultGenerator().reseed(additionalInput);
}

/** Return a non-sensitive snapshot of the shared generator's state. */
export function stats(): GeneratorStats {
  return getDefaultGenerator().stats();
}
