/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Tool-layer IO seam for the selective-disclosure (ecdsa-sd-2023) path: build a
 * P-256 did:key driver, a document loader that resolves did:key offline, and
 * derive a P-256 did:key issuer from a secret-key multibase. The ECDSA analog
 * of didKeyContext.js; purely additive (Phase 2).
 */
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import * as vcjs from '@digitalbazaar/vc';
import {ECDSA_MULTIKEY_HEADER, importEcdsaMultikey} from '../core/ecdsa.js';
import {createDocumentLoader} from '../core/documentLoader.js';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';

/**
 * @typedef {import('../core/documentLoader.js').DocumentLoader} DocumentLoader
 */

/**
 * Build a did:key driver wired for P-256 ECDSA multikeys.
 *
 * @returns {import('@digitalbazaar/did-method-key').DidKeyDriver} The driver.
 */
export function makeEcdsaDidKeyDriver() {
  const driver = didKeyDriverFactory();
  driver.use({
    multibaseMultikeyHeader: ECDSA_MULTIKEY_HEADER,
    fromMultibase: EcdsaMultikey.from
  });
  return driver;
}

/**
 * Build a cached document loader that resolves P-256 did:key offline and falls
 * back to the @digitalbazaar/vc default loader for standard contexts.
 *
 * @param {import('@digitalbazaar/did-method-key').DidKeyDriver} [driver] - An
 *   optional pre-built P-256 did:key driver; one is created if omitted.
 * @returns {DocumentLoader} The document loader.
 */
export function makeEcdsaDocumentLoader(driver = makeEcdsaDidKeyDriver()) {
  return createDocumentLoader({
    didKeyDriver: driver,
    fallbackLoader: vcjs.defaultDocumentLoader
  });
}

/**
 * @typedef {object} EcdsaDidKeyIssuer
 * @property {string} did The derived P-256 did:key issuer DID.
 * @property {object} signer The assertion-method signer for the key.
 */

/**
 * @typedef {object} EcdsaKeyMaterial
 * @property {string} publicKeyMultibase The P-256 public-key multibase.
 * @property {string} secretKeyMultibase The P-256 secret-key multibase.
 */

/**
 * Derive a P-256 did:key issuer (DID + signer) from its keypair multibase.
 * ECDSA multikeys cannot reconstruct the public key from the secret alone, so
 * both multibase parts are required.
 *
 * @param {EcdsaKeyMaterial} keyMaterial - The P-256 keypair multibase.
 * @param {import('@digitalbazaar/did-method-key').DidKeyDriver} driver - The
 *   P-256 did:key driver used to derive the DID document.
 * @returns {Promise<EcdsaDidKeyIssuer>} The issuer DID and its signer.
 */
export async function deriveEcdsaDidKeyIssuer(keyMaterial, driver) {
  const keyPair = await importEcdsaMultikey(keyMaterial);
  const {didDocument, methodFor} = await driver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const vm = methodFor({purpose: 'assertionMethod'});
  keyPair.id = vm.id;
  keyPair.controller = didDocument.id;
  return {did: didDocument.id, signer: keyPair.signer()};
}
