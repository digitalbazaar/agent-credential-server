/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/ecdsa-multikey.
//
// Why this exists: ecdsa-multikey ships no types, and no @types package is
// published. These hand-written declarations let `tsc --checkJs` resolve the
// P-256 key generation, signing, and import calls used by lib/core/ecdsa.js
// and the selective-disclosure path (Phase 2). Pure type metadata — no runtime
// code — covering only the surface this project uses.
//
// Lifetime: PERMANENT while Phase 2 selective disclosure is supported.
// ecdsa-multikey is the ECDSA analog of ed25519-multikey; remove ONLY if
// upstream begins shipping types.
declare module '@digitalbazaar/ecdsa-multikey' {
  interface Signer {
    algorithm: string;
    id: string;
    sign(options: {data: Uint8Array}): Promise<Uint8Array>;
  }

  interface Verifier {
    algorithm: string;
    id: string;
    verify(options: {
      data: Uint8Array;
      signature: Uint8Array;
    }): Promise<boolean>;
  }

  interface ExportOptions {
    publicKey?: boolean;
    secretKey?: boolean;
    raw?: boolean;
    includeContext?: boolean;
  }

  export interface EcdsaMultikeyPair {
    id?: string;
    controller?: string;
    type?: string;
    publicKeyMultibase: string;
    secretKeyMultibase?: string;
    signer(): Signer;
    verifier(): Verifier;
    export(options: ExportOptions): Promise<
      Record<string, unknown> & {
        publicKeyMultibase: string;
        secretKeyMultibase?: string;
      }
    >;
  }

  interface Jwk {
    kty: string;
    crv: string;
    x: string;
    y: string;
    d?: string;
  }

  export function generate(options?: {
    curve?: string;
    id?: string;
    controller?: string;
  }): Promise<EcdsaMultikeyPair>;

  export function from(key: {
    publicKeyMultibase?: string;
    secretKeyMultibase?: string;
    [key: string]: unknown;
  }): Promise<EcdsaMultikeyPair>;

  export function fromJwk(options: {
    jwk: Jwk;
    secretKey?: boolean;
  }): Promise<EcdsaMultikeyPair>;

  export function toJwk(options: {
    keyPair: EcdsaMultikeyPair;
    secretKey?: boolean;
  }): Promise<Jwk>;

  export function fromRaw(options: {
    curve: string;
    publicKey?: Uint8Array;
    secretKey?: Uint8Array;
  }): Promise<EcdsaMultikeyPair>;
}
