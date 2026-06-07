/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Response sanitizer for the web shell. No IO — pure, testable in isolation.
 *
 * The web demo issues real credentials with real ephemeral keys server-side.
 * Only public artifacts (the VC, the DIDs, the decision) may cross to the
 * browser. This recursively strips any field that could carry private key
 * material or a live signer, so the leakage-canary property (KYA-OS R-X-2: no
 * key material in any response) is enforced in code, not by convention.
 */

/**
 * Field names that must never appear in a response. Matched case-insensitively
 * against object keys. A signer is a live object holding a private key, so it
 * is stripped along with the raw key fields.
 *
 * @type {readonly string[]}
 */
export const FORBIDDEN_KEYS = Object.freeze([
  'privatekey',
  'privatekeybase64url',
  'privatekeymultibase',
  'secretkey',
  'secretkeymultibase',
  'signer',
  'sign',
  'd' // the JWK private scalar
]);

/**
 * @typedef {object} SanitizeResult
 * @property {unknown} value - The input with forbidden fields removed.
 * @property {string[]} stripped - Dot-paths of the fields that were stripped
 *   (for the canary test and an audit log).
 */

/**
 * Recursively remove any forbidden (key-material or signer) field from a value,
 * returning the cleaned copy and the paths that were stripped. Arrays, plain
 * objects, and primitives are handled; the input is not mutated.
 *
 * @param {unknown} value - The value to sanitize (typically a result object).
 * @returns {SanitizeResult} The cleaned value and the stripped field paths.
 */
export function sanitize(value) {
  /** @type {string[]} */
  const stripped = [];
  const cleaned = walk(value, '', stripped);
  return {value: cleaned, stripped};
}

/**
 * Walk a value, copying it while dropping forbidden keys and recording paths.
 *
 * @param {unknown} value - The current value.
 * @param {string} path - The dot-path to this value from the root.
 * @param {string[]} stripped - Accumulator for stripped field paths.
 * @returns {unknown} The cleaned value.
 */
function walk(value, path, stripped) {
  if(Array.isArray(value)) {
    return value.map((item, i) => walk(item, `${path}[${i}]`, stripped));
  }
  if(value !== null && typeof value === 'object') {
    /** @type {Record<string, unknown>} */
    const out = {};
    for(const [key, child] of Object.entries(value)) {
      if(FORBIDDEN_KEYS.includes(key.toLowerCase())) {
        stripped.push(path ? `${path}.${key}` : key);
        continue;
      }
      out[key] = walk(child, path ? `${path}.${key}` : key, stripped);
    }
    return out;
  }
  // a function (e.g. a bare signer) is never serializable to a client
  if(typeof value === 'function') {
    stripped.push(path);
    return undefined;
  }
  return value;
}
