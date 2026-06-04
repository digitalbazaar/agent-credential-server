/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {deriveDisclosure} from '../core/vcSd.js';
import {makeEcdsaDocumentLoader} from './sdContext.js';

/**
 * ISO/IEC 18013-5 caps a reader at requesting at most this many age_over_NN
 * elements per transaction (R-L3-6, §5.2).
 */
const MAX_AGE_OVER_FLAGS = 2;

/**
 * @typedef {object} DeriveDisclosureInput
 * @property {Record<string, unknown>} credential The base SD credential.
 * @property {string[]} revealClaims The credentialSubject claim names to
 *   disclose, e.g. ['age_over_21'].
 */

/**
 * Derive a reveal document disclosing only the requested credentialSubject
 * claims. Enforces the ISO reader-side age_over_NN limit before deriving.
 *
 * @param {DeriveDisclosureInput} input - The base credential and the claim
 *   names to reveal.
 * @returns {Promise<Record<string, unknown>>} The reveal document.
 */
export async function deriveDisclosureTool(input) {
  const {credential, revealClaims} = input;

  // KYA-OS R-L3-6: reject a request for more than two age_over_NN flags
  const ageFlags = revealClaims.filter(c => /^age_over_\d+$/.test(c));
  if(ageFlags.length > MAX_AGE_OVER_FLAGS) {
    throw new Error(
      `A disclosure may request at most ${MAX_AGE_OVER_FLAGS} age_over_NN ` +
      `flags; got ${ageFlags.length}.`);
  }

  const selectivePointers = revealClaims.map(c => `/credentialSubject/${c}`);
  return deriveDisclosure({
    credential,
    selectivePointers,
    documentLoader: makeEcdsaDocumentLoader()
  });
}
