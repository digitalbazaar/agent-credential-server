/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Ambient type declarations for @digitalbazaar/zcap.
//
// Why this exists: zcap ships no types and has no @types package (and an empty
// README). These hand-written declarations let `tsc --checkJs` resolve the
// capability helpers used by the chain loader and the verifyChain tool. Pure
// type metadata — no runtime code — covering only the surface this project
// uses. Remove ONLY if upstream begins shipping types.
declare module '@digitalbazaar/zcap' {
  interface RootCapability {
    '@context': string;
    id: string;
    controller: string;
    invocationTarget: string;
  }

  export function createRootCapability(options: {
    controller: string;
    invocationTarget: string;
  }): RootCapability;

  export function extendDocumentLoader(
    documentLoader: (url: string) => Promise<unknown>
  ): (url: string) => Promise<{
    contextUrl: string | null;
    documentUrl: string;
    document: Record<string, unknown>;
  }>;

  export const documentLoader: (url: string) => Promise<unknown>;

  export const constants: {
    ZCAP_CONTEXT_URL: string;
    ZCAP_CONTEXT: Record<string, unknown>;
    [key: string]: unknown;
  };

  export class CapabilityDelegation {
    constructor(options: {
      parentCapability?: string | object;
      expectedRootCapability?: string | string[];
      suite?: unknown;
      inspectCapabilityChain?: unknown;
      _capabilityChain?: unknown;
    });
  }

  export class CapabilityInvocation {
    constructor(options: {
      capability?: string | object;
      capabilityAction?: string;
      invocationTarget?: string;
      expectedTarget?: string | string[];
      expectedRootCapability?: string | string[];
      expectedAction?: string;
      suite?: unknown;
      inspectCapabilityChain?: unknown;
    });
  }
}
