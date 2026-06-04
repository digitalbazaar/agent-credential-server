/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/ecdsa-sd-2023-cryptosuite.
//
// Why this exists: the cryptosuite ships no types, and no @types package is
// published. This lets `tsc --checkJs` resolve the three SD cryptosuite
// factories passed to DataIntegrityProof in vcSd.js. Pure type metadata — no
// runtime code. Remove ONLY if upstream begins shipping types.
declare module '@digitalbazaar/ecdsa-sd-2023-cryptosuite' {
  export function createSignCryptosuite(options: {
    mandatoryPointers: string[];
  }): unknown;

  export function createDiscloseCryptosuite(options: {
    selectivePointers: string[];
  }): unknown;

  export function createVerifyCryptosuite(): unknown;

  export function createConfirmCryptosuite(): unknown;
}
