/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for base58-universal.
//
// Why this exists: base58-universal ships no types, and no @types/base58-universal
// package is published. These hand-written declarations let `tsc --checkJs`
// resolve the multibase encode/decode calls in crypto.js. The file is pure type
// metadata — no runtime code — and is isolated here in lib/types/.
//
// When to remove: only if upstream begins shipping types (or an @types package
// appears). Do NOT delete merely to reduce file count — the imports would fall
// back to `any` and silently lose type checking. This declaration lives as long
// as crypto.js (or anything else) imports base58-universal directly; a future
// refactor that routes all base58 work through @digitalbazaar/ed25519-multikey
// would make it removable.
declare module 'base58-universal' {
  export function encode(input: Uint8Array, maxline?: number): string;
  export function decode(input: string): Uint8Array;
}
