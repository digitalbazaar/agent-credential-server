/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/ed25519-multikey.
//
// Why this exists: ed25519-multikey ships no types, and no
// @types/digitalbazaar__ed25519-multikey package is published. These
// hand-written declarations let `tsc --checkJs` resolve the key generation,
// signing, and verification calls used across crypto.js (and, in later Phase 1
// steps, vc.js and the tools). Pure type metadata — no runtime code — covering
// only the surface this project uses.
//
// Lifetime: PERMANENT for the foreseeable future. ed25519-multikey is the
// central dependency of the DB-stack end-state (keys, signers, did:key, Data
// Integrity all flow through it), so this file is a real type contract, not
// migration scaffolding. Do NOT delete it when Phase 1 completes — that would
// turn the most-used library into `any` and silently propagate untyped values
// (e.g. the Multikey typedef in crypto.js) across the codebase. Remove ONLY if
// upstream begins shipping types or an @types package appears.
declare module '@digitalbazaar/ed25519-multikey' {
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

  interface ExportedRawKey {
    publicKey?: Uint8Array;
    secretKey?: Uint8Array;
  }

  interface Ed25519MultikeyPair {
    id?: string;
    controller?: string;
    type?: string;
    publicKeyMultibase: string;
    secretKeyMultibase?: string;
    signer(): Signer;
    verifier(): Verifier;
    export(options: ExportOptions): Promise<ExportedRawKey & Record<
      string, unknown
    >>;
  }

  interface Jwk {
    kty: string;
    crv: string;
    x: string;
    d?: string;
  }

  export function generate(options?: {
    id?: string;
    controller?: string;
  }): Promise<Ed25519MultikeyPair>;

  export function from(key: {
    publicKeyMultibase?: string;
    secretKeyMultibase?: string;
    [key: string]: unknown;
  }): Promise<Ed25519MultikeyPair>;

  export function fromJwk(options: {
    jwk: Jwk;
    secretKey?: boolean;
  }): Promise<Ed25519MultikeyPair>;

  export function toJwk(options: {
    keyPair: Ed25519MultikeyPair;
    secretKey?: boolean;
  }): Promise<Jwk>;
}
