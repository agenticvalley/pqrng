/**
 * @packageDocumentation
 * Barrel for the cryptographic layer: the DRBG, its entropy sources, the SHAKE256
 * seam, and the strength registry. Higher layers import from here so the concrete
 * primitives stay behind one door.
 */

export { ShakeDrbg, type DrbgSeed } from './drbg.js';
export {
  systemEntropySource,
  latticeConditionedEntropySource,
  defaultEntropySource,
  type EntropySource,
} from './entropy.js';
export {
  SEEDLEN,
  DEFAULT_SECURITY_STRENGTH,
  SECURITY_STRENGTHS,
  SUPPORTED_STRENGTHS,
  getStrengthProfile,
  isSecurityStrength,
  type SecurityStrength,
  type StrengthProfile,
  type MlKemName,
} from './strength.js';
export { shake256Xof } from './xof.js';
