/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import * as vcjs from '@digitalbazaar/vc';
import {issueCredentialDI, verifyCredentialDI} from '../core/vc.js';
import {createDocumentLoader} from '../core/documentLoader.js';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';

/**
 * @typedef {import('@digitalbazaar/did-method-key').DidKeyDriver} DidKeyDriver
 * @typedef {import('../core/documentLoader.js').DocumentLoader} DocumentLoader
 */

/**
 * Build a did:key driver wired for Ed25519.
 *
 * @returns {DidKeyDriver} A configured did:key driver.
 */
function makeDidKeyDriver() {
  const driver = didKeyDriverFactory();
  driver.use({
    multibaseMultikeyHeader: 'z6Mk',
    fromMultibase: Ed25519Multikey.from
  });
  return driver;
}

/**
 * @typedef {object} Issuer
 * @property {string} did The issuer did:key.
 * @property {object} signer The assertion-method signer.
 * @property {DocumentLoader} documentLoader An offline did:key loader.
 */

/**
 * Build a did:key issuer (key + signer + loader) for tests.
 *
 * @returns {Promise<Issuer>} The issuer context.
 */
async function makeIssuer() {
  const driver = makeDidKeyDriver();
  const keyPair = await Ed25519Multikey.generate();
  const {didDocument, methodFor} = await driver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const vm = methodFor({purpose: 'assertionMethod'});
  keyPair.id = vm.id;
  keyPair.controller = didDocument.id;
  const documentLoader = createDocumentLoader({
    didKeyDriver: driver,
    fallbackLoader: vcjs.defaultDocumentLoader
  });
  return {did: didDocument.id, signer: keyPair.signer(), documentLoader};
}

const AGENT_DID = 'did:example:agent';

describe('issueCredentialDI', () => {
  it('issues a VC 2.0 with an eddsa-rdfc-2022 proof', async () => {
    const {did, signer, documentLoader} = await makeIssuer();
    const signed = await issueCredentialDI({
      issuerDid: did,
      subjectDid: AGENT_DID,
      claims: {over_21: true},
      signer,
      documentLoader
    });
    expect(signed.proof.type).toBe('DataIntegrityProof');
    expect(signed.proof.cryptosuite).toBe('eddsa-rdfc-2022');
    expect(signed.issuer).toBe(did);
    expect(signed.credentialSubject.id).toBe(AGENT_DID);
  });

  it('keeps an arbitrary claim term via the bundled context', async () => {
    const {did, signer, documentLoader} = await makeIssuer();
    const signed = await issueCredentialDI({
      issuerDid: did,
      subjectDid: AGENT_DID,
      claims: {clearance: 'top-secret'},
      signer,
      documentLoader
    });
    // safe mode would drop an undefined term; the @vocab fallback keeps it
    expect(signed.credentialSubject.clearance).toBe('top-secret');
  });
});

describe('verifyCredentialDI', () => {
  it('verifies a freshly issued credential', async () => {
    const {did, signer, documentLoader} = await makeIssuer();
    const signed = await issueCredentialDI({
      issuerDid: did,
      subjectDid: AGENT_DID,
      claims: {age_verified: true, over_21: true},
      signer,
      documentLoader
    });
    const result = await verifyCredentialDI({
      credential: signed, documentLoader
    });
    expect(result.valid).toBe(true);
    expect(result.issuer).toBe(did);
    expect(result.subject).toBe(AGENT_DID);
    expect(result.claims).toMatchObject({age_verified: true, over_21: true});
  });

  it('rejects a tampered credentialSubject', async () => {
    const {did, signer, documentLoader} = await makeIssuer();
    const signed = await issueCredentialDI({
      issuerDid: did,
      subjectDid: AGENT_DID,
      claims: {over_21: true},
      signer,
      documentLoader
    });
    const tampered = JSON.parse(JSON.stringify(signed));
    tampered.credentialSubject.over_21 = false;
    const result = await verifyCredentialDI({
      credential: tampered, documentLoader
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/verif|proof|signature/i);
  });

  it('rejects an expired credential', async () => {
    const {did, signer, documentLoader} = await makeIssuer();
    // expire well beyond the 300s default clock skew
    const signed = await issueCredentialDI({
      issuerDid: did,
      subjectDid: AGENT_DID,
      claims: {over_21: true},
      expiresInSeconds: -3600,
      signer,
      documentLoader
    });
    const result = await verifyCredentialDI({
      credential: signed, documentLoader
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/validUntil|expired/i);
  });

  it('rejects a credential signed by a different key', async () => {
    const issuer = await makeIssuer();
    const impostor = await makeIssuer();
    // issue with impostor's signer but claim the real issuer DID
    const forged = await issueCredentialDI({
      issuerDid: issuer.did,
      subjectDid: AGENT_DID,
      claims: {over_21: true},
      signer: impostor.signer,
      documentLoader: issuer.documentLoader
    });
    const result = await verifyCredentialDI({
      credential: forged, documentLoader: issuer.documentLoader
    });
    expect(result.valid).toBe(false);
  });
});
