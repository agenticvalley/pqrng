/**
 * @packageDocumentation
 * The deterministic random bit generator (DRBG).
 *
 * This is a faithful realization of the **NIST SP 800-90A `Hash_DRBG`**
 * construction, with one deliberate substitution: every place the standard calls
 * for an approved hash and its `Hash_df` derivation function, we use
 * **SHAKE256** (FIPS-202). Because SHAKE256 is an extendable-output function, the
 * standard's counter-driven `Hash_df` and `Hashgen` loops collapse into a single
 * "absorb, then squeeze N bytes" call — simpler, and with no truncation of the
 * hash's security.
 *
 * The state machine and its guarantees are exactly SP 800-90A's:
 *
 * - **Working state** `(V, C, reseed_counter)`, with `V` and `C` each
 *   {@link SEEDLEN} bytes wide.
 * - **Instantiate** derives `V` and `C` from entropy ‖ nonce ‖ personalization.
 * - **Reseed** folds fresh entropy back into `V` and re-derives `C`.
 * - **Generate** squeezes output from `V`, then performs the backtracking-
 *   resistant state update `V ← V + H + C + reseed_counter (mod 2^seedlen)`.
 *
 * The DRBG holds no opinion about *where* entropy comes from: it is injected by
 * the caller (see `entropy.ts`). That keeps this module a pure, testable state
 * machine.
 */

import { GeneratorStateError, ErrorCode } from '../errors.js';
import { addModPow2, concatBytes, wipe } from '../utils/bytes.js';
import { SEEDLEN } from './strength.js';
import { shake256Xof } from './xof.js';

/** Domain-separation prefix for deriving `C` from `V` (SP 800-90A: `0x00 ‖ V`). */
const PREFIX_C = Uint8Array.of(0x00);
/** Domain-separation prefix for the reseed seed-material (`0x01 ‖ V ‖ …`). */
const PREFIX_RESEED = Uint8Array.of(0x01);
/** Domain-separation prefix for folding in additional input (`0x02 ‖ V ‖ addl`). */
const PREFIX_ADDITIONAL = Uint8Array.of(0x02);
/** Domain-separation prefix for the state-update value `H` (`0x03 ‖ V`). */
const PREFIX_UPDATE = Uint8Array.of(0x03);

/** An empty byte string, reused to avoid per-call allocation. */
const EMPTY = new Uint8Array(0);

/** Seed material required to instantiate a {@link ShakeDrbg}. */
export interface DrbgSeed {
  /** Entropy input from an approved source (SP 800-90A §8.6.3). */
  readonly entropy: Uint8Array;
  /** A nonce, contributing further seeding diversity (SP 800-90A §8.6.7). */
  readonly nonce: Uint8Array;
  /** Optional personalization string; defaults to empty. */
  readonly personalization?: Uint8Array;
  /** Maximum `generate` calls between reseeds before {@link ShakeDrbg.needsReseed} is set. */
  readonly reseedInterval: number;
}

/**
 * A SHAKE256-based `Hash_DRBG` (NIST SP 800-90A).
 *
 * Instances are stateful and **not** thread-safe in the sense that concurrent
 * `generate` calls from different async contexts would interleave state updates;
 * in Node's single-threaded model a synchronous `generate` is atomic, which is
 * how the higher-level generator uses it.
 */
export class ShakeDrbg {
  /** Working-state value `V` ({@link SEEDLEN} bytes). Secret. */
  private v: Uint8Array;
  /** Working-state constant `C` ({@link SEEDLEN} bytes). Secret. */
  private c: Uint8Array;
  /** Number of `generate` calls since the last (re)seed; starts at 1. */
  private counter: number;
  /** The configured reseed interval. */
  private readonly reseedInterval: number;
  /** Whether {@link destroy} has been called. */
  private destroyed = false;

  /**
   * Instantiate the DRBG from seed material (SP 800-90A §10.1.1.2).
   *
   * @param seed - Entropy, nonce, optional personalization, and reseed interval.
   */
  public constructor(seed: DrbgSeed) {
    this.reseedInterval = seed.reseedInterval;
    // V = Hash_df(entropy ‖ nonce ‖ personalization)
    this.v = shake256Xof(SEEDLEN, concatBytes(seed.entropy, seed.nonce, seed.personalization ?? EMPTY));
    // C = Hash_df(0x00 ‖ V)
    this.c = shake256Xof(SEEDLEN, PREFIX_C, this.v);
    this.counter = 1;
  }

  /** `true` once the number of `generate` calls has exceeded the reseed interval. */
  public needsReseed(): boolean {
    return this.counter > this.reseedInterval;
  }

  /** `generate` calls performed since the last (re)seed. */
  public get reseedCounter(): number {
    return this.counter;
  }

  /**
   * Reseed the DRBG with fresh entropy (SP 800-90A §10.1.1.3).
   *
   * Folds `entropy` (and optional `additionalInput`) into the current `V`,
   * re-derives `C`, and resets the reseed counter — restoring full forward
   * secrecy and prediction resistance.
   *
   * @param entropy - Fresh entropy input from an approved source.
   * @param additionalInput - Optional extra input to mix in; defaults to empty.
   */
  public reseed(entropy: Uint8Array, additionalInput: Uint8Array = EMPTY): void {
    this.assertLive();
    // seed_material = 0x01 ‖ V ‖ entropy_input ‖ additional_input
    const v = shake256Xof(SEEDLEN, concatBytes(PREFIX_RESEED, this.v, entropy, additionalInput));
    wipe(this.v, this.c);
    this.v = v;
    this.c = shake256Xof(SEEDLEN, PREFIX_C, this.v);
    this.counter = 1;
  }

  /**
   * Produce `numBytes` of output and advance the state (SP 800-90A §10.1.1.4).
   *
   * @param numBytes - Number of output bytes to squeeze (must be ≥ 0).
   * @param additionalInput - Optional extra input mixed into `V` before output.
   * @returns Exactly `numBytes` pseudorandom bytes.
   * @throws {GeneratorStateError} If a reseed is required first, or the DRBG was destroyed.
   */
  public generate(numBytes: number, additionalInput: Uint8Array = EMPTY): Uint8Array {
    this.assertLive();
    if (this.needsReseed()) {
      throw new GeneratorStateError(
        'DRBG reseed interval reached; reseed before generating more output',
        ErrorCode.RESEED_REQUIRED,
        { context: { reseedCounter: this.counter, reseedInterval: this.reseedInterval } },
      );
    }

    // Optionally fold caller-supplied additional input into V: V = (V + w) mod 2^seedlen,
    // where w = Hash(0x02 ‖ V ‖ additional_input).
    if (additionalInput.length > 0) {
      const w = shake256Xof(SEEDLEN, PREFIX_ADDITIONAL, this.v, additionalInput);
      const mixed = addModPow2(this.v, w);
      wipe(this.v);
      this.v = mixed;
    }

    // Output: squeeze numBytes straight from V (SHAKE256 as the Hashgen).
    const output = shake256Xof(numBytes, this.v);

    // Backtracking-resistant state update: V = (V + H + C + reseed_counter) mod 2^seedlen,
    // with H = Hash(0x03 ‖ V). H is derived from a domain-separated input, so it is
    // independent of `output` and cannot be recovered from it.
    const h = shake256Xof(SEEDLEN, PREFIX_UPDATE, this.v);
    const nextV = addModPow2(this.v, h, this.c, BigInt(this.counter));
    wipe(this.v);
    this.v = nextV;
    this.counter += 1;

    return output;
  }

  /**
   * Irreversibly wipe the secret state. After this the instance throws on use.
   */
  public destroy(): void {
    wipe(this.v, this.c);
    this.destroyed = true;
  }

  /** Guard every public operation against use-after-destroy. */
  private assertLive(): void {
    if (this.destroyed) {
      throw new GeneratorStateError('DRBG has been destroyed', ErrorCode.GENERATOR_DESTROYED);
    }
  }
}
