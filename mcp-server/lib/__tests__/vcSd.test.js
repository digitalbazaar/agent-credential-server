/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure ecdsa-sd-2023 selective-disclosure logic: issue a base proof, derive a
 * reveal document, verify it. The did:key driver + document loader are built
 * here (offline P-256 did:key) and injected, so these run without network.
 */
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {
  deriveDisclosure, issueSdCredential, verifyDisclosure
} from '../core/vcSd.js';
import {createDocumentLoader} from '../core/documentLoader.js';
import {defaultDocumentLoader} from '@digitalbazaar/vc';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';
import {ECDSA_MULTIKEY_HEADER} from '../core/ecdsa.js';

/**
 * @typedef {import('../core/documentLoader.js').DocumentLoader} DocumentLoader
 */

/**
 * Build a P-256 did:key issuer + the project's offline document loader (which
 * serves the agent-credential context and did:key without network).
 *
 * @returns {Promise<{
 *   did: string, signer: object, documentLoader: DocumentLoader
 * }>} The issuer DID, its signer, and a did:key-aware loader.
 */
async function makeIssuer() {
  const driver = didKeyDriverFactory();
  driver.use({
    multibaseMultikeyHeader: ECDSA_MULTIKEY_HEADER,
    fromMultibase: EcdsaMultikey.from
  });
  const keyPair = await EcdsaMultikey.generate({curve: 'P-256'});
  const {didDocument, methodFor} = await driver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const vm = methodFor({purpose: 'assertionMethod'});
  keyPair.id = vm.id;
  keyPair.controller = didDocument.id;
  const documentLoader = createDocumentLoader({
    didKeyDriver: driver,
    fallbackLoader: defaultDocumentLoader
  });
  return {did: didDocument.id, signer: keyPair.signer(), documentLoader};
}

const AGENT_DID = 'did:example:agent';
const MANDATORY = ['/issuer', '/validFrom', '/validUntil'];

/**
 * Issue a base SD credential carrying age flags + hidden PII.
 *
 * @param {{did: string, signer: object, documentLoader: DocumentLoader}} ctx
 *   The issuer context from makeIssuer.
 * @returns {Promise<Record<string, unknown>>} The signed base credential.
 */
async function issueBase(ctx) {
  return issueSdCredential({
    issuerDid: ctx.did,
    subjectDid: AGENT_DID,
    claims: {
      birthdate: '2000-01-01',
      age_over_18: true,
      age_over_21: true,
      age_over_65: false,
      name: 'Pat Holder'
    },
    mandatoryPointers: MANDATORY,
    signer: ctx.signer,
    documentLoader: ctx.documentLoader,
    validFromInSeconds: -1,
    expiresInSeconds: 3600
  });
}

describe('issueSdCredential', () => {
  it('issues a base proof with the ecdsa-sd-2023 cryptosuite', async () => {
    const ctx = await makeIssuer();
    const base = await issueBase(ctx);
    const proof = /** @type {{cryptosuite: string}} */ (base.proof);
    expect(proof.cryptosuite).toBe('ecdsa-sd-2023');
    expect(base.issuer).toBe(ctx.did);
  });
});

describe('deriveDisclosure', () => {
  it('reveals only the requested claim, hiding the rest', async () => {
    const ctx = await makeIssuer();
    const base = await issueBase(ctx);
    const revealed = await deriveDisclosure({
      credential: base,
      selectivePointers: ['/credentialSubject/age_over_21'],
      documentLoader: ctx.documentLoader
    });
    const subject = /** @type {Record<string, unknown>} */ (
      revealed.credentialSubject
    );
    expect(subject.age_over_21).toBe(true);
    // hidden claims must be absent (R-L3-1)
    expect(subject.birthdate).toBeUndefined();
    expect(subject.name).toBeUndefined();
    expect(subject.age_over_18).toBeUndefined();
    expect(subject.age_over_65).toBeUndefined();
  });
});

describe('verifyDisclosure', () => {
  it('verifies a genuine reveal document', async () => {
    const ctx = await makeIssuer();
    const base = await issueBase(ctx);
    const revealed = await deriveDisclosure({
      credential: base,
      selectivePointers: ['/credentialSubject/age_over_21'],
      documentLoader: ctx.documentLoader
    });
    const result = await verifyDisclosure({
      revealDocument: revealed, documentLoader: ctx.documentLoader
    });
    expect(result.valid).toBe(true);
    expect(result.issuer).toBe(ctx.did);
    const claims = result.revealedClaims ?? {};
    expect(claims.age_over_21).toBe(true);
  });

  it('rejects a tampered reveal document (R-L3-2)', async () => {
    const ctx = await makeIssuer();
    const base = await issueBase(ctx);
    const revealed = await deriveDisclosure({
      credential: base,
      selectivePointers: ['/credentialSubject/age_over_21'],
      documentLoader: ctx.documentLoader
    });
    const tampered = JSON.parse(JSON.stringify(revealed));
    tampered.credentialSubject.age_over_21 = false;
    const result = await verifyDisclosure({
      revealDocument: tampered, documentLoader: ctx.documentLoader
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/verif|proof|signature/i);
  });

  it('returns a structured result, never throws, on a malformed doc',
    async () => {
      const ctx = await makeIssuer();
      const result = await verifyDisclosure({
        revealDocument: {not: 'a credential'},
        documentLoader: ctx.documentLoader
      });
      expect(result.valid).toBe(false);
      expect(result.reason).toEqual(expect.any(String));
    });
});
