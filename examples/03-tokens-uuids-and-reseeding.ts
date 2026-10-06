/**
 * Example 03 — Tokens, UUIDs, reseeding, and deterministic mode.
 *
 * Run: `npm run example:tokens`
 *
 * Covers the operational features: minting URL-safe secrets and identifiers,
 * forcing a reseed, reading the generator's non-sensitive stats, and using a
 * fixed seed to get a fully reproducible stream (for tests and simulations).
 */

import { Alphabets, createGenerator } from '../src/index.js';

const rng = createGenerator();

console.log('=== Tokens & identifiers ===\n');
console.log('API key (32 bytes)  :', rng.randomBase64Url(32));
console.log('Session id (16 B)   :', rng.randomHex(16));
console.log('Numeric OTP (6)     :', rng.randomString(6, { alphabet: Alphabets.numeric }));
console.log('Base58 handle (12)  :', rng.randomString(12, { alphabet: Alphabets.base58 }));
console.log('UUIDv4              :', rng.uuidV4(), '(random)');
console.log('UUIDv7              :', rng.uuidV7(), '(time-ordered)');

console.log('\n=== Reseeding ===\n');
console.log('before reseed:', rng.stats());
rng.reseed('operational-context-label');
console.log('after  reseed:', rng.stats(), '(reseeds incremented, counter reset)');

console.log('\n=== Deterministic mode (tests only) ===\n');
const seed = new TextEncoder().encode('reproducible-seed-value');
const a = createGenerator({ seed });
const b = createGenerator({ seed });
console.log('stream A:', a.randomHex(16));
console.log('stream B:', b.randomHex(16));
console.log('identical:', a.randomHex(16) === b.randomHex(16), '(same seed → same stream)');
console.log('\nNever use a fixed seed for real secrets — it is, by design, fully predictable.');
