/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {makeSdDidKeyDriver, makeSdDocumentLoader} from './sdContext.js';
import {verifyDisclosure} from '../core/vcSd.js';

/**
 * @typedef {import('../core/vcSd.js').VerifyDisclosureResult}
 *   VerifyDisclosureResult
 * @typedef {import('../core/vcSd.js').SdCryptosuite} SdCryptosuite
 */

/**
 * @typedef {object} VerifyDisclosureToolInput
 * @property {Record<string, unknown>} revealDocument The reveal document to
 *   verify.
 * @property {SdCryptosuite} [cryptosuite] The SD cryptosuite the reveal
 *   document was derived with; defaults to ecdsa-sd-2023.
 */

/**
 * Verify a reveal document's derived selective-disclosure proof. Wires the
 * offline did:key loader (matching the cryptosuite's key type) to the pure
 * verify core.
 *
 * @param {VerifyDisclosureToolInput} input - The reveal document.
 * @returns {Promise<VerifyDisclosureResult>} The verification result.
 */
export async function verifyDisclosureTool(input) {
  const {cryptosuite} = input;
  return verifyDisclosure({
    revealDocument: input.revealDocument,
    documentLoader: makeSdDocumentLoader(makeSdDidKeyDriver(cryptosuite)),
    cryptosuite
  });
}
