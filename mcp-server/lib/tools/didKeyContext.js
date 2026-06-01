/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Tool-layer helpers for the Data Integrity path: build a did:key driver, a
 * cached document loader, and derive a did:key issuer from a raw private key.
 * This is the IO-orchestration seam — it wires the pure documentLoader factory
 * to a concrete did:key driver and the @digitalbazaar/vc default loader.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import * as vcjs from '@digitalbazaar/vc';
import {createDocumentLoader} from '../core/documentLoader.js';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';

/**
 * @typedef {import('../core/documentLoader.js').DocumentLoader} DocumentLoader
 */

/**
 * Build a did:key driver wired for Ed25519.
 *
 * @returns {import('@digitalbazaar/did-method-key').DidKeyDriver} The driver.
 */
export function makeDidKeyDriver() {
  const driver = didKeyDriverFactory();
  driver.use({
    multibaseMultikeyHeader: 'z6Mk',
    fromMultibase: Ed25519Multikey.from
  });
  return driver;
}

/**
 * Build a cached document loader that resolves did:key offline and falls back
 * to the @digitalbazaar/vc default loader for standard contexts.
 *
 * @param {import('@digitalbazaar/did-method-key').DidKeyDriver} [driver] - An
 *   optional pre-built did:key driver; one is created if omitted.
 * @returns {DocumentLoader} The document loader.
 */
export function makeDocumentLoader(driver = makeDidKeyDriver()) {
  return createDocumentLoader({
    didKeyDriver: driver,
    fallbackLoader: vcjs.defaultDocumentLoader
  });
}

/**
 * @typedef {object} DidKeyIssuer
 * @property {string} did The derived did:key issuer DID.
 * @property {object} signer The assertion-method signer for the key.
 */

/**
 * Derive a did:key issuer (DID + signer) from a raw 32-byte Ed25519 seed.
 *
 * @param {Uint8Array} privateKey - The raw 32-byte Ed25519 seed.
 * @param {import('@digitalbazaar/did-method-key').DidKeyDriver} driver - The
 *   did:key driver used to derive the DID document.
 * @returns {Promise<DidKeyIssuer>} The issuer DID and its signer.
 */
export async function deriveDidKeyIssuer(privateKey, driver) {
  // reconstruct a multikey from the raw seed via its JWK form, then derive
  // the did:key document so the issuer DID matches the signing key
  const {getPublicKeyAsync} = await import('@noble/ed25519');
  const publicKey = await getPublicKeyAsync(privateKey);
  const toB64u = (/** @type {Uint8Array} */ b) =>
    Buffer.from(b).toString('base64url');
  const keyPair = await Ed25519Multikey.fromJwk({
    jwk: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: toB64u(publicKey),
      d: toB64u(privateKey)
    },
    secretKey: true
  });

  const {didDocument, methodFor} = await driver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const vm = methodFor({purpose: 'assertionMethod'});
  keyPair.id = vm.id;
  keyPair.controller = didDocument.id;
  return {did: didDocument.id, signer: keyPair.signer()};
}
