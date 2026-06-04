/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {makeEcdsaDocumentLoader} from './sdContext.js';
import {verifyDisclosure} from '../core/vcSd.js';

/**
 * @typedef {import('../core/vcSd.js').VerifyDisclosureResult}
 *   VerifyDisclosureResult
 */

/**
 * @typedef {object} VerifyDisclosureToolInput
 * @property {Record<string, unknown>} revealDocument The reveal document to
 *   verify.
 */

/**
 * Verify a reveal document's derived ecdsa-sd-2023 proof. Wires the offline
 * P-256 did:key loader to the pure verify core.
 *
 * @param {VerifyDisclosureToolInput} input - The reveal document.
 * @returns {Promise<VerifyDisclosureResult>} The verification result.
 */
export async function verifyDisclosureTool(input) {
  return verifyDisclosure({
    revealDocument: input.revealDocument,
    documentLoader: makeEcdsaDocumentLoader()
  });
}
