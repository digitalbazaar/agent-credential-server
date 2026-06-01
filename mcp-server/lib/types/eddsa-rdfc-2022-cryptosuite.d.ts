/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/eddsa-rdfc-2022-cryptosuite.
//
// Why this exists: the cryptosuite ships no types, and no @types package is
// published. This lets `tsc --checkJs` resolve the cryptosuite passed to
// DataIntegrityProof in vc.js. Pure type metadata — no runtime code. Remove
// ONLY if upstream begins shipping types.
declare module '@digitalbazaar/eddsa-rdfc-2022-cryptosuite' {
  export const cryptosuite: unknown;
}
