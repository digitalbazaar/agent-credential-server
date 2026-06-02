/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Authorization-capability (zcap) chain helpers.
 * No IO of its own — the did:key driver is injected, and the zcap, data
 * integrity, and root-capability documents are served from bundled or
 * in-memory constants. The actual chain verification is performed by
 * @digitalbazaar/zcap via jsonld-signatures in the tool layer.
 */
import * as diContext from '@digitalbazaar/data-integrity-context';
import * as zcap from '@digitalbazaar/zcap';
import {createDocumentLoader} from './documentLoader.js';

const {createRootCapability} = zcap;

/**
 * @typedef {import('./documentLoader.js').DocumentLoader} DocumentLoader
 * @typedef {import('@digitalbazaar/did-method-key').DidKeyDriver} DidKeyDriver
 */

/**
 * A root authorization capability. Uses object-literal typedef syntax so the
 * `@context` key can be quoted.
 *
 * @typedef {{
 *   '@context': string,
 *   id: string,
 *   controller: string,
 *   invocationTarget: string
 * }} RootCapability
 */

/**
 * Build a root authorization capability for a controller and target.
 *
 * @param {object} input - The root capability parameters.
 * @param {string} input.controller - The controller DID (the root authority).
 * @param {string} input.invocationTarget - The protected resource URL.
 * @returns {RootCapability} The root capability.
 */
export function buildRootCapability(input) {
  return createRootCapability({
    controller: input.controller,
    invocationTarget: input.invocationTarget
  });
}

/**
 * @typedef {object} CreateZcapLoaderInput
 * @property {DidKeyDriver} didKeyDriver - The did:key driver for controllers.
 * @property {RootCapability[]} [rootCapabilities] - Root capabilities to serve
 *   by id (delegation chains reference the root by id, not by embedding it).
 * @property {DocumentLoader} [fallbackLoader] - Loader for any other URL.
 */

/**
 * Create a cached document loader for zcap chain verification. Serves the zcap
 * context, the data-integrity contexts, the did:key controller documents, and
 * the registered root capabilities — all offline.
 *
 * @param {CreateZcapLoaderInput} input - The driver, roots, and fallback.
 * @returns {DocumentLoader} The zcap-aware document loader.
 */
export function createZcapDocumentLoader(input) {
  const {didKeyDriver, rootCapabilities = [], fallbackLoader} = input;

  const roots = new Map(rootCapabilities.map(r => [r.id, r]));
  const base = createDocumentLoader({didKeyDriver, fallbackLoader});

  // zcap.extendDocumentLoader serves the zcap context and delegates the rest
  return zcap.extendDocumentLoader(async function documentLoader(url) {
    // 1. registered root capability — referenced by id in the chain
    const root = roots.get(url);
    if(root) {
      return {contextUrl: null, documentUrl: url, document: root};
    }

    // 2. data-integrity contexts — zcap proofs reference data-integrity/v2
    if(diContext.contexts.has(url)) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: diContext.contexts.get(url)
      };
    }

    // 3. did:key controllers and bundled VC contexts via the base loader
    return base(url);
  });
}

/**
 * @typedef {object} LeafControllerResult
 * @property {boolean} valid
 * @property {string} [reason]
 */

/**
 * Assert that a delegated capability's controller is the expected agent. The
 * zcap library verifies the chain's cryptographic continuity but not that the
 * leaf was delegated to a specific agent DID; this closes that gap.
 *
 * @param {object} input - The check parameters.
 * @param {{controller?: string}} input.capability - The leaf capability.
 * @param {string} input.expectedController - The expected agent DID.
 * @returns {LeafControllerResult} Whether the controller matches.
 */
export function checkLeafController(input) {
  const {capability, expectedController} = input;
  if(capability.controller !== expectedController) {
    return {
      valid: false,
      reason: `Leaf controller (${capability.controller}) does not match ` +
        `expected agent (${expectedController})`
    };
  }
  return {valid: true};
}
