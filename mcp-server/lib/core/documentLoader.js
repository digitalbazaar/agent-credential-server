/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * JSON-LD document loader for Data Integrity issue/verify.
 * No IO of its own — the network is an injected dependency. The did:key
 * resolution and the bundled context documents are deterministic and offline,
 * so this core module stays testable in isolation; only the injected
 * fallbackLoader may perform IO, and the tool layer decides what that is.
 */

/**
 * Stable URL for the agent-credential claim context. Served locally from the
 * bundled constant below; publishing a resolvable document is deferred to a
 * later phase.
 */
export const AGENT_CREDENTIAL_CONTEXT_URL =
  'https://w3id.org/agent-credential/v1';

/**
 * The agent-credential claim context. Defines the demo claim terms so JSON-LD
 * safe mode keeps them, with an @vocab fallback so arbitrary claims still
 * expand to an absolute IRI instead of being dropped.
 */
export const AGENT_CREDENTIAL_CONTEXT = Object.freeze({
  '@context': {
    '@vocab': 'https://w3id.org/agent-credential#',
    age_verified: 'https://w3id.org/agent-credential#age_verified',
    over_21: 'https://w3id.org/agent-credential#over_21',
    delegatedFrom: 'https://w3id.org/agent-credential#delegatedFrom',
    role: 'https://w3id.org/agent-credential#role'
  }
});

/**
 * @typedef {object} DocumentLoaderResult
 * @property {string | null} contextUrl The context URL, or null.
 * @property {string} documentUrl The resolved document URL.
 * @property {Record<string, unknown>} document The resolved JSON-LD document.
 */

/**
 * @callback DocumentLoader
 * @param {string} url - The URL to resolve.
 * @returns {Promise<DocumentLoaderResult>} The loaded document.
 */

/**
 * @typedef {import('@digitalbazaar/did-method-key').DidKeyDriver} DidKeyDriver
 */

/**
 * @typedef {object} CreateDocumentLoaderInput
 * @property {DidKeyDriver} didKeyDriver - A configured did:key driver whose
 *   get({url}) returns a DID document (or verification method for #fragment
 *   URLs) directly.
 * @property {DocumentLoader} [fallbackLoader] - Loader for URLs this loader
 *   does not handle natively, such as other context documents; may perform IO.
 */

// Locally bundled @context documents, keyed by URL, served without network.
const BUNDLED_CONTEXTS = new Map([
  [AGENT_CREDENTIAL_CONTEXT_URL, AGENT_CREDENTIAL_CONTEXT]
]);

/**
 * Create a cached JSON-LD document loader for Data Integrity.
 *
 * @param {CreateDocumentLoaderInput} input - The did:key driver and an
 *   optional fallback loader.
 * @returns {DocumentLoader} A cached document loader.
 */
export function createDocumentLoader(input) {
  const {didKeyDriver, fallbackLoader} = input;
  /** @type {Map<string, DocumentLoaderResult>} */
  const cache = new Map();

  /** @type {DocumentLoader} */
  return async function documentLoader(url) {
    // 1. Cache hit — return the exact same object (offline, no rework)
    const cached = cache.get(url);
    if(cached) {
      return cached;
    }

    // 2. Bundled @context document — served from memory, never the network
    const bundled = BUNDLED_CONTEXTS.get(url);
    if(bundled) {
      /** @type {DocumentLoaderResult} */
      const result = {
        contextUrl: null,
        documentUrl: url,
        document: /** @type {Record<string, unknown>} */ (bundled)
      };
      cache.set(url, result);
      return result;
    }

    // 3. did:key — deterministic, offline; the driver returns the document
    //    (or verification method for a #fragment) DIRECTLY, not wrapped
    if(url.startsWith('did:key:')) {
      const document = await didKeyDriver.get({url});
      /** @type {DocumentLoaderResult} */
      const result = {
        contextUrl: null,
        documentUrl: url,
        document: /** @type {Record<string, unknown>} */ (
          /** @type {unknown} */ (document)
        )
      };
      cache.set(url, result);
      return result;
    }

    // 4. Anything else — defer to the injected fallback (may perform IO)
    if(fallbackLoader) {
      const result = await fallbackLoader(url);
      cache.set(url, result);
      return result;
    }

    // 5. No handler — fail with a clear reason
    throw new Error(`Document loader: unsupported URL "${url}".`);
  };
}
