# Changelog

All notable changes to `@agenticvalley/pqrng` are documented in this file. The
format follows the Keep a Changelog convention, and this project adheres to
Semantic Versioning.

## [0.1.1] - 2026-09-28

### Changed

- **Docs.** Replaced the README's Mermaid pipeline diagram with an ASCII
  equivalent so the "How a value is produced" section renders correctly on npm
  (whose README viewer does not support Mermaid), not just on GitHub.

## [0.1.0] - 2026-09-27

### Added

- **Post-quantum-only CSPRNG.** A reseedable NIST **SP 800-90A `Hash_DRBG`**
  realized with **SHAKE256** (FIPS-202) — the same Keccak sponge underpinning
  ML-KEM/ML-DSA — over a 512-bit working state, giving a ~128-bit Grover margin.
  No AES-CTR-DRBG, no truncated-hash DRBG, no classical fallback.
- **ML-KEM lattice entropy conditioning.** The default entropy source passes the
  OS CSPRNG through an **ML-KEM** (FIPS-203) encapsulation and folds the
  lattice-derived shared secret and ciphertext back in with SHAKE256, so every
  byte reaching the DRBG has passed exclusively through post-quantum primitives.
  A system-only source and custom sources are also supported.
- **Ergonomic generator surface** on both `PostQuantumRandom` and matching
  package-level free functions backed by a shared instance:
  - Bytes/integers — `randomBytes`, `randomUint32`, `randomBelow`, `randomInt`,
    `randomIntInclusive`, `randomBigInt`, `randomBigIntInRange`.
  - Floats/booleans/strings — `randomFloat` (full 53-bit), `randomBoolean`,
    `randomString` (with ready-made `Alphabets`), `randomHex`, `randomBase64Url`.
  - Identifiers — `uuid` (alias for `uuidV4`), `uuidV4`, and time-ordered
    `uuidV7` (RFC 9562).
  - Collections — `choice`, `sample` (without replacement), `shuffle`,
    `shuffleInPlace` (all unbiased Fisher–Yates / rejection sampling).
- **Unbiased by construction.** Every bounded helper uses masked rejection
  sampling, eliminating modulo bias while terminating in < 2 draws on average.
- **Three security strengths** — `128`, `192`, and `256` (default) — sharing one
  SHAKE256 core and mapped to `ML-KEM-512` / `ML-KEM-768` / `ML-KEM-1024`.
- **Deterministic mode.** A fixed `seed` yields a fully reproducible stream for
  tests and simulations (with automatic reseeding disabled).
- **Automatic reseeding** at the strength's reseed interval, plus explicit
  `reseed(additionalInput?)`, a non-sensitive `stats()` snapshot, and `destroy()`
  with best-effort state zeroization.
- **Dual ESM + CommonJS packaging.** Ships both an ES-module and a CommonJS
  build with per-format type declarations, so `import pqrng from '@agenticvalley/pqrng'` and
  `const pqrng = require('@agenticvalley/pqrng')` both work on any supported Node version.
- **Typed error hierarchy** with stable `ErrorCode`s: `InvalidArgumentError`,
  `EmptyRangeError`, `UnsupportedStrengthError`, `InvalidSeedError`,
  `EntropySourceError`, and `GeneratorStateError`.
- **Tests** covering DRBG determinism and reseeding, distribution uniformity,
  range/UUID correctness, error paths, and both entropy sources — with coverage
  thresholds enforced.
