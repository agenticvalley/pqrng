/**
 * Example 02 — Integers, ranges, and choosing from collections.
 *
 * Run: `npm run example:ranges`
 *
 * Shows the bounded-integer helpers (all unbiased) and the collection utilities
 * `choice`, `sample`, and `shuffle`. A quick histogram demonstrates that the
 * output really is uniform.
 */

import { createGenerator } from '../src/index.js';

const rng = createGenerator();

console.log('=== Integers & ranges ===\n');
console.log('randomBelow(10)           :', rng.randomBelow(10), '(0..9)');
console.log('randomInt(1, 7)           :', rng.randomInt(1, 7), '(1..6, a d6)');
console.log('randomIntInclusive(1, 100):', rng.randomIntInclusive(1, 100), '(1..100)');
console.log('randomBigInt(2n ** 128n)  :', rng.randomBigInt(2n ** 128n).toString());

console.log('\n=== Choosing from collections ===\n');
const suits = ['♣', '♦', '♥', '♠'] as const;
const ranks = ['A', '2', '3', '4', '5', '6', '7', '8', '9', '10', 'J', 'Q', 'K'] as const;
const deck = suits.flatMap((suit) => ranks.map((rank) => `${rank}${suit}`));

console.log('choice(deck)      :', rng.choice(deck));
console.log('sample(deck, 5)   :', rng.sample(deck, 5).join(' '), '(a poker hand, no repeats)');
console.log('shuffle(1..6)     :', rng.shuffle([1, 2, 3, 4, 5, 6]).join(' '));

console.log('\n=== Uniformity check: 600,000 d6 rolls ===\n');
const histogram = [0, 0, 0, 0, 0, 0];
for (let i = 0; i < 600_000; i++) {
  histogram[rng.randomBelow(6)]++;
}
histogram.forEach((count, face) => {
  const bar = '█'.repeat(Math.round(count / 5000));
  console.log(`  ${face + 1} | ${bar} ${count}`);
});
console.log('\nEach face should land near 100,000 — an unbiased, rejection-sampled distribution.');
