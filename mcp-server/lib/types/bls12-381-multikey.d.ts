/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/bls12-381-multikey.
//
// Why this exists: bls12-381-multikey ships no types, and no @types package is
// published. These hand-written declarations let `tsc --checkJs` resolve the
// BBS key generation, signing, and import calls used by lib/core/bls.js and
// the unlinkable selective-disclosure path (Phase 2.5). Pure type metadata —
// no runtime code — covering only the surface this project uses.
//
// Lifetime: PERMANENT while Phase 2.5 BBS disclosure is supported. The BLS
// analog of ed25519-multikey/ecdsa-multikey; remove ONLY if upstream begins
// shipping types.
declare module '@digitalbazaar/bls12-381-multikey' {
  interface Signer {
    algorithm: string;
    id: string;
    sign(options: {data: Uint8Array}): Promise<Uint8Array>;
    multisign?(options: {data: Uint8Array[]}): Promise<Uint8Array>;
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

  export interface BlsMultikeyPair {
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
    d?: string;
  }

  export const ALGORITHMS: Record<string, string>;

  export function generateBbsKeyPair(options: {
    algorithm: string;
    id?: string;
    controller?: string;
  }): Promise<BlsMultikeyPair>;

  export function from(key: {
    publicKeyMultibase?: string;
    secretKeyMultibase?: string;
    [key: string]: unknown;
  }): Promise<BlsMultikeyPair>;

  export function fromJwk(options: {
    jwk: Jwk;
    secretKey?: boolean;
  }): Promise<BlsMultikeyPair>;

  export function fromRaw(options: {
    algorithm: string;
    publicKey?: Uint8Array;
    secretKey?: Uint8Array;
  }): Promise<BlsMultikeyPair>;

  export function toJwk(options: {
    keyPair: BlsMultikeyPair;
    secretKey?: boolean;
  }): Promise<Jwk>;
}
