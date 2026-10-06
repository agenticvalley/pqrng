/**
 * @packageDocumentation
 * Time helpers.
 *
 * The generator itself is timeless, but a couple of conveniences built on top of
 * it — most notably time-ordered **UUIDv7** — need a millisecond clock. Routing
 * every clock read through here means those helpers can be made deterministic in
 * tests by injecting a fixed clock, exactly as the cryptographic core can be made
 * deterministic by injecting a fixed seed.
 */

/** A function returning the current time in epoch **milliseconds** (like {@link Date.now}). */
export type Clock = () => number;

/** The default clock, backed by {@link Date.now}. */
export const systemClock: Clock = () => Date.now();
