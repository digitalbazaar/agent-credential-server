/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Tool-layer IO seam for the selective-disclosure paths: build a did:key
 * driver, a document loader that resolves did:key offline, and derive an
 * issuer from a keypair multibase. Cryptosuite-aware — ecdsa-sd-2023 uses
 * P-256 ECDSA keys (zDna), bbs-2023 uses BLS12-381 keys (zUC6/zUC7) — so the
 * same seam serves both. Purely additive (Phase 2/2.5).
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {BLS_MULTIKEY_HEADERS, importBlsMultikey} from '../core/bls.js';
import {ECDSA_MULTIKEY_HEADER, importEcdsaMultikey} from '../core/ecdsa.js';
import {createDocumentLoader} from '../core/documentLoader.js';
import {defaultDocumentLoader} from '@digitalbazaar/vc';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';

/**
 * @typedef {import('../core/documentLoader.js').DocumentLoader} DocumentLoader
 * @typedef {import('../core/vcSd.js').SdCryptosuite} SdCryptosuite
 */

// Per-cryptosuite key wiring: the did:key multibase header(s), the multikey
// module's `from` (for the driver), and the project's import helper (which
// validates the header). `headers` is a list because BLS12-381 G2 keys have
// two possible 4-char prefixes (zUC6/zUC7); each must be registered with the
// driver. One row per supported SD cryptosuite.
/** @type {Record<string, SdKeyWiring>} */
const SD_KEYS = {
  'ecdsa-sd-2023': {
    headers: [ECDSA_MULTIKEY_HEADER],
    fromMultibase: EcdsaMultikey.from,
    importMultikey: importEcdsaMultikey
  },
  'bbs-2023': {
    headers: BLS_MULTIKEY_HEADERS,
    fromMultibase: Bls12381Multikey.from,
    importMultikey: importBlsMultikey
  }
};

/**
 * @typedef {object} SdKeyWiring
 * @property {readonly string[]} headers - The did:key multibase header(s) the
 *   driver must register for this key type.
 * @property {(key: any) => Promise<any>} fromMultibase - The multikey module's
 *   `from`, for the did:key driver.
 * @property {(key: any) => Promise<any>} importMultikey - The project's
 *   header-validating import helper.
 */

/**
 * Resolve the key wiring for a cryptosuite, defaulting to ecdsa-sd-2023.
 *
 * @param {SdCryptosuite} [cryptosuite] - The SD cryptosuite.
 * @returns {SdKeyWiring} The key wiring.
 */
function resolveKeyWiring(cryptosuite = 'ecdsa-sd-2023') {
  const wiring = SD_KEYS[cryptosuite];
  if(!wiring) {
    throw new Error(
      `Unknown cryptosuite "${cryptosuite}". Supported: ` +
      `${Object.keys(SD_KEYS).join(', ')}.`);
  }
  return wiring;
}

/**
 * Build a did:key driver wired for the cryptosuite's key type.
 *
 * @param {SdCryptosuite} [cryptosuite] - The SD cryptosuite.
 * @returns {import('@digitalbazaar/did-method-key').DidKeyDriver} The driver.
 */
export function makeSdDidKeyDriver(cryptosuite) {
  const {headers, fromMultibase} = resolveKeyWiring(cryptosuite);
  const driver = didKeyDriverFactory();
  // register every valid multibase header for this key type (BLS12-381 G2 has
  // two, zUC6/zUC7, depending on the key bytes)
  for(const multibaseMultikeyHeader of headers) {
    driver.use({multibaseMultikeyHeader, fromMultibase});
  }
  return driver;
}

/**
 * Build a cached document loader that resolves the cryptosuite's did:key
 * offline and falls back to the @digitalbazaar/vc default loader.
 *
 * @param {import('@digitalbazaar/did-method-key').DidKeyDriver} [driver] - A
 *   pre-built did:key driver; one is created (ecdsa) if omitted.
 * @returns {DocumentLoader} The document loader.
 */
export function makeSdDocumentLoader(driver = makeSdDidKeyDriver()) {
  return createDocumentLoader({
    didKeyDriver: driver,
    fallbackLoader: defaultDocumentLoader
  });
}

/**
 * @typedef {object} SdDidKeyIssuer
 * @property {string} did The derived did:key issuer DID.
 * @property {object} signer The assertion-method signer for the key.
 */

/**
 * @typedef {object} SdKeyMaterial
 * @property {string} publicKeyMultibase The public-key multibase.
 * @property {string} secretKeyMultibase The secret-key multibase.
 */

/**
 * Derive a did:key issuer (DID + signer) from its keypair multibase, for the
 * given cryptosuite's key type. Both multibase parts are required (neither
 * ECDSA nor BLS reconstructs the public key from the secret alone).
 *
 * @param {SdKeyMaterial} keyMaterial - The keypair multibase.
 * @param {import('@digitalbazaar/did-method-key').DidKeyDriver} driver - The
 *   did:key driver matching the key type.
 * @param {SdCryptosuite} [cryptosuite] - The SD cryptosuite.
 * @returns {Promise<SdDidKeyIssuer>} The issuer DID and its signer.
 */
export async function deriveSdDidKeyIssuer(keyMaterial, driver, cryptosuite) {
  const {importMultikey} = resolveKeyWiring(cryptosuite);
  const keyPair = await importMultikey(keyMaterial);
  const {didDocument, methodFor} = await driver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const vm = methodFor({purpose: 'assertionMethod'});
  keyPair.id = vm.id;
  keyPair.controller = didDocument.id;
  return {did: didDocument.id, signer: keyPair.signer()};
}
