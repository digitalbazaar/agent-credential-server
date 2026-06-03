/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * DID resolution.
 * IO boundary — mocked in tests.
 *
 * The did:web method is resolved natively (a direct fetch of the host's
 * did.json), so the common case needs no third-party service. Every other
 * method falls back to the Universal Resolver. The did:web URL transformation
 * is pure and lives in ./didWeb.js.
 */
import {didWebToUrl} from './didWeb.js';

const UNIVERSAL_RESOLVER_BASE = 'https://dev.uniresolver.io/1.0/identifiers';

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
 * @param {string} did - The DID to resolve.
 * @returns {Promise<ResolutionResult>} The resolution result with DID document.
 */
export async function resolveDID(did) {
  // did:web resolves natively; the fallback covers it only if the direct
  // fetch fails (host down, non-2xx, or unparseable did.json).
  const webUrl = didWebToUrl(did);
  if(webUrl) {
    const native = await resolveDIDWeb(webUrl);
    if(native.didDocument) {
      return native;
    }
  }

  return resolveViaUniversalResolver(did);
}

/**
 * Resolve a did:web DID by fetching its did.json directly.
 *
 * @param {string} url - The HTTPS did.json URL from `didWebToUrl`.
 * @returns {Promise<ResolutionResult>} The resolution result; `didDocument` is
 *   null with an error when the fetch or parse fails.
 */
async function resolveDIDWeb(url) {
  try {
    const res = await fetch(url, {headers: {Accept: 'application/json'}});
    if(!res.ok) {
      return {
        didDocument: null,
        didResolutionMetadata: {error: `HTTP ${res.status}: ${res.statusText}`}
      };
    }
    const didDocument = await res.json();
    return {didDocument, didResolutionMetadata: {contentType: 'did:web'}};
  } catch(err) {
    return {
      didDocument: null,
      didResolutionMetadata: {error: `did:web fetch failed: ${err}`}
    };
  }
}

/**
 * Resolve any DID via the Universal Resolver service.
 *
 * @param {string} did - The DID to resolve.
 * @returns {Promise<ResolutionResult>} The resolution result.
 */
async function resolveViaUniversalResolver(did) {
  const url = `${UNIVERSAL_RESOLVER_BASE}/${encodeURIComponent(did)}`;
  const res = await fetch(url, {
    headers: {Accept: 'application/json'}
  });

  if(!res.ok) {
    return {
      didDocument: null,
      didResolutionMetadata: {
        error: `HTTP ${res.status}: ${res.statusText}`
      }
    };
  }

  const body = await res.json();
  return body;
}
