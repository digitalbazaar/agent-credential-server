/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/data-integrity.
//
// Why this exists: data-integrity ships no types, and no @types package is
// published. These hand-written declarations let `tsc --checkJs` resolve the
// DataIntegrityProof suite used by vc.js. Pure type metadata — no runtime code.
// Remove ONLY if upstream begins shipping types.
declare module '@digitalbazaar/data-integrity' {
  export class DataIntegrityProof {
    constructor(options: {signer?: unknown; cryptosuite: unknown});
    type: string;
    cryptosuite: unknown;
  }
}
