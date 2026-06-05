/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure BLS12-381 multikey utilities for unlinkable selective disclosure
 * (Phase 2.5, bbs-2023). No IO — testable in isolation.
 *
 * The bbs-2023 suite requires BLS12-381 keys, a third key type distinct from
 * the Ed25519 (auth/zcap) and P-256 ECDSA (ecdsa-sd-2023) keys. This is the
 * BLS analog of ecdsa.js, built on @digitalbazaar/bls12-381-multikey. Purely
 * additive: nothing here touches the Ed25519 or ECDSA paths.
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';

/**
 * The BLS12-381 G2 multibase (multikey) prefix. The did:key driver and the
 * document loader use this to recognize a BBS key, the way `z6Mk` flags
 * Ed25519 and `zDna` flags P-256 ECDSA.
 */
export const BLS_MULTIKEY_HEADER = 'zUC7';

/**
 * The signature algorithm bbs-2023 requires (the SHA-256 BBS suite over
 * BLS12-381).
 */
export const BLS_SD_ALGORITHM = 'BBS-BLS12-381-SHA-256';

/**
 * @typedef {import('@digitalbazaar/bls12-381-multikey').BlsMultikeyPair}
 *   BlsMultikeyPair
 */

/**
 * Generate a fresh BLS12-381 BBS multikey.
 *
 * @returns {Promise<BlsMultikeyPair>} A new BBS multikey with a signer.
 */
export async function generateBlsMultikey() {
  return Bls12381Multikey.generateBbsKeyPair({algorithm: BLS_SD_ALGORITHM});
}

/**
 * @typedef {object} ImportBlsInput
 * @property {string} publicKeyMultibase - The z-prefixed BLS12-381 public key.
 * @property {string} [secretKeyMultibase] - The secret key, to import a signer.
 * @property {string} [id] - The verification method id.
 * @property {string} [controller] - The controller DID.
 */

/**
 * Import a BLS12-381 BBS multikey from its multibase material. A public-only
 * import yields a verify-only key; including the secret yields a signer.
 *
 * @param {ImportBlsInput} input - The multikey material to import.
 * @returns {Promise<BlsMultikeyPair>} The imported multikey.
 */
export async function importBlsMultikey(input) {
  if(!input?.publicKeyMultibase?.startsWith(BLS_MULTIKEY_HEADER)) {
    throw new Error(
      `Not a BLS12-381 BBS multikey: expected a "${BLS_MULTIKEY_HEADER}" ` +
      'publicKeyMultibase prefix.');
  }
  return Bls12381Multikey.from(input);
}
