/**
 * @packageDocumentation
 * Textual encodings for random bytes.
 *
 * A random *number* generator is, at the primitive level, a random *byte*
 * generator. The moment those bytes leave the library they usually need a
 * string form — a hex nonce, a URL-safe token, a base64url identifier — so we
 * centralize the two encodings we support here and delegate the bit-twiddling
 * to audited implementations rather than hand-rolling it.
 */

import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { base64urlnopad } from '@scure/base';
import { ErrorCode, PqRngError } from '../errors.js';

export { bytesToHex, hexToBytes };

/**
 * Encode raw bytes as unpadded base64url (RFC 4648 §5).
 *
 * base64url is the URL- and filename-safe Base64 alphabet (`+`→`-`, `/`→`_`)
 * with trailing `=` padding removed, so the result can travel unescaped in a
 * URL, an HTTP header, or a cookie.
 *
 * @param bytes - The bytes to encode.
 * @returns The base64url string, without `=` padding.
 */
export function base64UrlEncode(bytes: Uint8Array): string {
  return base64urlnopad.encode(bytes);
}

/**
 * Decode an unpadded base64url string back into raw bytes.
 *
 * @param text - The base64url text to decode.
 * @returns The decoded bytes.
 * @throws {PqRngError} With code {@link ErrorCode.ENCODING} if `text` contains
 *   characters outside the base64url alphabet.
 */
export function base64UrlDecode(text: string): Uint8Array {
  try {
    return base64urlnopad.decode(text);
  } catch (cause) {
    throw new PqRngError('value is not valid base64url', ErrorCode.ENCODING, { cause });
  }
}
