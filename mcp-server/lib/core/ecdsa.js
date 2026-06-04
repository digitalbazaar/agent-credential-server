/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure P-256 ECDSA multikey utilities for selective disclosure (Phase 2).
 * No IO — testable in isolation.
 *
 * Selective disclosure (ecdsa-sd-2023) requires ECDSA keys, distinct from the
 * Ed25519 keys the rest of the stack uses. This module is the ECDSA analog of
 * the multikey surface in crypto.js, built on @digitalbazaar/ecdsa-multikey.
 * It is purely additive: nothing here touches the Ed25519 path.
 */
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';

/**
 * The P-256 multibase (multikey) prefix. The did:key driver and the document
 * loader use this to recognize an ECDSA P-256 key, the way `z6Mk` flags
 * Ed25519.
 */
export const ECDSA_MULTIKEY_HEADER = 'zDna';

/**
 * @typedef {import('@digitalbazaar/ecdsa-multikey').EcdsaMultikeyPair}
 *   EcdsaMultikeyPair
 */

/**
 * Generate a fresh P-256 ECDSA multikey.
 *
 * @returns {Promise<EcdsaMultikeyPair>} A new P-256 multikey with a signer.
 */
export async function generateEcdsaMultikey() {
  return EcdsaMultikey.generate({curve: 'P-256'});
}

/**
 * @typedef {object} ImportEcdsaInput
 * @property {string} publicKeyMultibase - The z-prefixed P-256 public key.
 * @property {string} [secretKeyMultibase] - The secret key, to import a signer.
 * @property {string} [id] - The verification method id.
 * @property {string} [controller] - The controller DID.
 */

/**
 * Import a P-256 ECDSA multikey from its multibase material. A public-only
 * import yields a verify-only key; including the secret yields a signer.
 *
 * @param {ImportEcdsaInput} input - The multikey material to import.
 * @returns {Promise<EcdsaMultikeyPair>} The imported multikey.
 */
export async function importEcdsaMultikey(input) {
  if(!input?.publicKeyMultibase?.startsWith(ECDSA_MULTIKEY_HEADER)) {
    throw new Error(
      `Not a P-256 ECDSA multikey: expected a "${ECDSA_MULTIKEY_HEADER}" ` +
      'publicKeyMultibase prefix.');
  }
  return EcdsaMultikey.from(input);
}
