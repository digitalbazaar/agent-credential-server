/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/vc-status-list.
//
// Why this exists: @digitalbazaar/vc-status-list ships no types, and no @types
// package is published. These hand-written declarations let `tsc --checkJs`
// resolve the createList/decodeList/StatusList calls in revocation.js and its
// test. Pure type metadata — no runtime code — covering only the surface this
// project uses. Remove ONLY if upstream begins shipping types.
declare module '@digitalbazaar/vc-status-list' {
  export class StatusList {
    length: number;
    constructor(options?: {length?: number; buffer?: Uint8Array});
    setStatus(index: number, status: boolean): void;
    getStatus(index: number): boolean;
    encode(): Promise<string>;
    static decode(options: {encodedList: string}): Promise<StatusList>;
  }

  export function createList(options: {length: number}): Promise<StatusList>;

  export function decodeList(
    options: {encodedList: string}
  ): Promise<StatusList>;
}
