/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/did-method-key.
//
// Why this exists: did-method-key ships no types, and no @types package is
// published. These hand-written declarations let `tsc --checkJs` resolve the
// did:key driver used by the document loader and the issue/verify tools. Pure
// type metadata — no runtime code — covering only the surface this project
// uses. Remove ONLY if upstream begins shipping types.
declare module '@digitalbazaar/did-method-key' {
  interface VerificationMethod {
    id: string;
    type: string;
    controller: string;
    publicKeyMultibase?: string;
  }

  interface DidDocument {
    '@context': unknown;
    id: string;
    verificationMethod: VerificationMethod[];
    authentication?: (string | VerificationMethod)[];
    assertionMethod?: (string | VerificationMethod)[];
  }

  export interface DidKeyDriver {
    use(options: {
      multibaseMultikeyHeader: string;
      fromMultibase: (key: never) => unknown;
    }): void;
    fromKeyPair(options: {verificationKeyPair: unknown}): Promise<{
      didDocument: DidDocument;
      keyPairs: Map<string, unknown>;
      methodFor: (options: {purpose: string}) => VerificationMethod;
    }>;
    get(options: {url: string}): Promise<DidDocument | VerificationMethod>;
    publicMethodFor(options: {
      didDocument: DidDocument;
      purpose: string;
    }): VerificationMethod;
  }

  export function driver(): DidKeyDriver;
  export function createFromMultibase(
    multikey: unknown
  ): (options: unknown) => Promise<unknown>;
}
