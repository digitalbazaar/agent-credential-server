/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/vc.
//
// Why this exists: @digitalbazaar/vc ships no types, and no @types package is
// published. These hand-written declarations let `tsc --checkJs` resolve the
// issue/verifyCredential/defaultDocumentLoader calls in vc.js and the document
// loader. Pure type metadata — no runtime code — covering only the surface
// this project uses. Remove ONLY if upstream begins shipping types.
declare module '@digitalbazaar/vc' {
  interface DocumentLoaderResult {
    contextUrl: string | null;
    documentUrl: string;
    document: Record<string, unknown>;
  }

  type DocumentLoader = (url: string) => Promise<DocumentLoaderResult>;

  interface VerifyCredentialResult {
    verified: boolean;
    error?: Error & {errors?: Error[]};
    results?: unknown[];
    statusResult?: unknown;
  }

  export function issue(options: {
    credential: Record<string, unknown>;
    suite: unknown;
    documentLoader: DocumentLoader;
    purpose?: unknown;
  }): Promise<Record<string, unknown>>;

  export function verifyCredential(options: {
    credential: Record<string, unknown>;
    suite: unknown;
    documentLoader: DocumentLoader;
    purpose?: unknown;
  }): Promise<VerifyCredentialResult>;

  export const defaultDocumentLoader: DocumentLoader;
}
