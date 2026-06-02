/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for jsonld-signatures.
//
// Why this exists: jsonld-signatures ships no types and has no @types package.
// This lets `tsc --checkJs` resolve the sign/verify calls used by the zcap
// chain tool. Pure type metadata — no runtime code. Remove ONLY if upstream
// begins shipping types.
declare module 'jsonld-signatures' {
  interface VerifyResult {
    verified: boolean;
    error?: Error & {errors?: Error[]};
    results?: unknown[];
  }

  interface JsonLdSignatures {
    sign(
      document: Record<string, unknown>,
      options: {
        suite: unknown;
        purpose: unknown;
        documentLoader: (url: string) => Promise<unknown>;
      }
    ): Promise<Record<string, unknown>>;
    verify(
      document: Record<string, unknown>,
      options: {
        suite: unknown;
        purpose: unknown;
        documentLoader: (url: string) => Promise<unknown>;
      }
    ): Promise<VerifyResult>;
    strictDocumentLoader: (url: string) => Promise<unknown>;
  }

  const jsigs: JsonLdSignatures;
  export default jsigs;
}
