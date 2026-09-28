/**
 * Post-build finalizer for the dual ESM/CJS package.
 *
 * The root `package.json` declares `"type": "module"`, so Node would treat every
 * `.js` under `dist/` as ESM. Dropping a tiny `package.json` into each build
 * directory overrides that per-folder: `dist/cjs` is marked CommonJS (so its
 * `require`/`module.exports` output loads correctly) and `dist/esm` is marked
 * ESM explicitly. This is the standard, bundler-free way to ship both formats.
 */

import { writeFileSync } from 'node:fs';

const targets = [
  { path: 'dist/cjs/package.json', type: 'commonjs' },
  { path: 'dist/esm/package.json', type: 'module' },
];

for (const { path, type } of targets) {
  writeFileSync(path, `${JSON.stringify({ type }, null, 2)}\n`);
  console.log(`wrote ${path} (${type})`);
}
