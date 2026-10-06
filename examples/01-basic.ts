/**
 * Example 01 — The basics.
 *
 * Run: `npm run example:basic`
 *
 * A tour of the zero-setup facade: every call below is backed by one shared,
 * post-quantum generator, so there is nothing to construct.
 */

import {
  randomBoolean,
  randomBytes,
  randomFloat,
  randomHex,
  randomInt,
  randomString,
  randomUint32,
  stats,
  uuidV4,
} from '../src/index.js';
import { bytesToHex } from '../src/utils/index.js';

console.log('=== @agenticvalley/pqrng — basics ===\n');

console.log('randomBytes(16) :', bytesToHex(randomBytes(16)));
console.log('randomUint32()  :', randomUint32());
console.log('randomInt(1, 7) :', randomInt(1, 7), '(a fair d6)');
console.log('randomFloat()   :', randomFloat(), '(in [0, 1))');
console.log('randomBoolean() :', randomBoolean(), '(a fair coin)');
console.log('randomBoolean(0.9):', randomBoolean(0.9), '(90% chance of true)');
console.log('randomHex(8)    :', randomHex(8));
console.log('randomString(24):', randomString(24), '(URL-safe base64url)');
console.log('uuidV4()        :', uuidV4());

console.log('\nGenerator state:', stats());
console.log('\nTip: every byte above came from a SHAKE256 DRBG seeded through an ML-KEM lattice stage.');
