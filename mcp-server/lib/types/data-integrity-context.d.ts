/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/data-integrity-context.
//
// Why this exists: the package ships no types and has no @types package. This
// lets `tsc --checkJs` resolve the bundled context map served by the zcap
// document loader. Pure type metadata — no runtime code. Remove ONLY if
// upstream begins shipping types.
declare module '@digitalbazaar/data-integrity-context' {
  export const contexts: Map<string, Record<string, unknown>>;
  export const CONTEXT_URL: string;
  export const DATA_INTEGRITY_CONTEXT_V1_URL: string;
  export const DATA_INTEGRITY_CONTEXT_V2_URL: string;
  export const CONTEXT: Record<string, unknown>;
}
