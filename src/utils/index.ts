/**
 * @packageDocumentation
 * Barrel for the internal utility layer, re-exporting the byte, encoding, and
 * time helpers so the rest of the library can import them from one place.
 */

export {
  addModPow2,
  bigIntToBytesBE,
  bytesToBigIntBE,
  concatBytes,
  copyBytes,
  randomBytes,
  readUint32BE,
  utf8ToBytes,
  wipe,
} from './bytes.js';
export { base64UrlDecode, base64UrlEncode, bytesToHex, hexToBytes } from './encoding.js';
export { systemClock, type Clock } from './time.js';
