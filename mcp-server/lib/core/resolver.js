/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Universal Resolver client.
 * IO boundary — mocked in tests.
 */

const UNIVERSAL_RESOLVER_BASE = "https://dev.uniresolver.io/1.0/identifiers";

/**
 * @typedef {object} VerificationMethod
 * @property {string} id
 * @property {string} type
 * @property {string} controller
 * @property {string} [publicKeyMultibase]
 * @property {Record<string, unknown>} [publicKeyJwk]
 * @property {string} [publicKeyBase58]
 */

/**
 * @typedef {object} DIDDocument
 * @property {string} id
 * @property {VerificationMethod[]} [verificationMethod]
 * @property {(string | VerificationMethod)[]} [authentication]
 * @property {(string | VerificationMethod)[]} [assertionMethod]
 */

/**
 * @typedef {object} ResolutionResult
 * @property {DIDDocument | null} didDocument
 * @property {{error?: string, [key: string]: unknown}} didResolutionMetadata
 */

/**
 * @param {string} did
 * @returns {Promise<ResolutionResult>}
 */
export async function resolveDID(did) {
  const url = `${UNIVERSAL_RESOLVER_BASE}/${encodeURIComponent(did)}`;
  const res = await fetch(url, {
    headers: { Accept: "application/json" },
  });

  if (!res.ok) {
    return {
      didDocument: null,
      didResolutionMetadata: {
        error: `HTTP ${res.status}: ${res.statusText}`,
      },
    };
  }

  const body = await res.json();
  return body;
}
