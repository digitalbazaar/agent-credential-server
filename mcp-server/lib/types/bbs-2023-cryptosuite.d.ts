/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/bbs-2023-cryptosuite.
//
// Why this exists: the cryptosuite ships no types, and no @types package is
// published. This lets `tsc --checkJs` resolve the three BBS SD cryptosuite
// factories passed to DataIntegrityProof in vcSd.js (Phase 2.5). Pure type
// metadata — no runtime code. Remove ONLY if upstream begins shipping types.
declare module '@digitalbazaar/bbs-2023-cryptosuite' {
  export function createSignCryptosuite(options: {
    mandatoryPointers: string[];
  }): unknown;

  export function createDiscloseCryptosuite(options: {
    selectivePointers: string[];
  }): unknown;

  export function createVerifyCryptosuite(): unknown;

  export const requiredAlgorithm: string[];
}
