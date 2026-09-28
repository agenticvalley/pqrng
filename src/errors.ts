/**
 * @packageDocumentation
 * Typed error hierarchy.
 *
 * Every failure this library raises is a {@link PqRngError} carrying a stable,
 * machine-readable {@link ErrorCode}. Consumers can branch on `.code` instead of
 * parsing message strings, and transport layers (HTTP, gRPC) can map codes to
 * status responses deterministically.
 *
 * The design reflects a common operational need: a caller usually needs to
 * distinguish "the caller asked for something impossible" (a programming error,
 * e.g. an empty range) from "the machine could not supply entropy" (an
 * environmental failure that warrants an alert rather than a retry).
 */

/**
 * Stable, machine-readable error codes.
 *
 * Codes are grouped by layer. Never renumber or repurpose an existing value —
 * only append — because downstream systems may switch on them.
 */
export enum ErrorCode {
  // --- Generic / input (1xxx) ----------------------------------------------
  /** A supplied argument was structurally invalid (wrong type, NaN, negative, …). */
  INVALID_ARGUMENT = 'E1000_INVALID_ARGUMENT',
  /** A requested feature, option, or combination is not supported. */
  UNSUPPORTED = 'E1001_UNSUPPORTED',
  /** A base64url / hex (de)serialization step failed. */
  ENCODING = 'E1002_ENCODING',
  /** A requested range or collection was empty, so nothing could be chosen. */
  EMPTY_RANGE = 'E1003_EMPTY_RANGE',

  // --- Configuration (2xxx) ------------------------------------------------
  /** The requested security strength is not one of the supported values. */
  UNSUPPORTED_STRENGTH = 'E2000_UNSUPPORTED_STRENGTH',
  /** A seed / personalization / additional-input value was the wrong shape. */
  INVALID_SEED = 'E2001_INVALID_SEED',

  // --- Entropy & DRBG state (3xxx) -----------------------------------------
  /** The underlying entropy source failed or returned too few bytes. */
  ENTROPY_SOURCE_FAILURE = 'E3000_ENTROPY_SOURCE_FAILURE',
  /** The generator has been destroyed and can no longer produce output. */
  GENERATOR_DESTROYED = 'E3001_GENERATOR_DESTROYED',
  /**
   * The DRBG reached its reseed interval and automatic reseeding is disabled,
   * so a fresh reseed is required before more output can be produced
   * (NIST SP 800-90A §9.3, the reseed-required condition).
   */
  RESEED_REQUIRED = 'E3002_RESEED_REQUIRED',
}

/** Structured, JSON-safe context attached to an error. */
export type ErrorContext = Record<string, string | number | boolean | null | undefined>;

/** Options accepted by every {@link PqRngError} constructor. */
export interface PqRngErrorOptions {
  /** Structured, JSON-safe context to aid debugging and logging. */
  readonly context?: ErrorContext;
  /** The underlying error that triggered this one, preserved for stack traces. */
  readonly cause?: unknown;
}

/**
 * Base class for every error raised by `pqrng`.
 *
 * @example Branch on a stable code
 * ```ts
 * try {
 *   random.randomInt(10, 5); // max <= min
 * } catch (err) {
 *   if (err instanceof PqRngError && err.code === ErrorCode.INVALID_ARGUMENT) {
 *     // a programming error in the call site, not an environmental failure
 *   }
 * }
 * ```
 */
export class PqRngError extends Error {
  /** Stable, machine-readable classification of this error. */
  public readonly code: ErrorCode;
  /** Structured, JSON-safe context to aid debugging and logging. */
  public readonly context?: ErrorContext;

  public constructor(message: string, code: ErrorCode, options: PqRngErrorOptions = {}) {
    // Forward `cause` to the native Error so stack traces chain correctly.
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = new.target.name;
    this.code = code;
    if (options.context !== undefined) {
      this.context = options.context;
    }
    // Restore the prototype chain when compiled down to ES5-style output.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** A supplied argument was structurally invalid (wrong type, NaN, out of range, …). */
export class InvalidArgumentError extends PqRngError {
  public constructor(message: string, options: PqRngErrorOptions = {}) {
    super(message, ErrorCode.INVALID_ARGUMENT, options);
  }
}

/** A requested range or collection was empty, so nothing could be chosen. */
export class EmptyRangeError extends PqRngError {
  public constructor(message: string, options: PqRngErrorOptions = {}) {
    super(message, ErrorCode.EMPTY_RANGE, options);
  }
}

/** The requested security strength is not one of the supported values. */
export class UnsupportedStrengthError extends PqRngError {
  public constructor(message: string, options: PqRngErrorOptions = {}) {
    super(message, ErrorCode.UNSUPPORTED_STRENGTH, options);
  }
}

/** A seed / personalization / additional-input value was the wrong shape. */
export class InvalidSeedError extends PqRngError {
  public constructor(message: string, options: PqRngErrorOptions = {}) {
    super(message, ErrorCode.INVALID_SEED, options);
  }
}

/** The underlying entropy source failed or returned too few bytes. */
export class EntropySourceError extends PqRngError {
  public constructor(message: string, options: PqRngErrorOptions = {}) {
    super(message, ErrorCode.ENTROPY_SOURCE_FAILURE, options);
  }
}

/**
 * The generator can no longer produce output — either it was explicitly
 * destroyed, or it needs a reseed that is not permitted automatically.
 */
export class GeneratorStateError extends PqRngError {
  public constructor(message: string, code: ErrorCode, options: PqRngErrorOptions = {}) {
    super(message, code, options);
  }
}
