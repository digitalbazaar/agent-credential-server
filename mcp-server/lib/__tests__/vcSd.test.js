/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure ecdsa-sd-2023 selective-disclosure logic: issue a base proof, derive a
 * reveal document, verify it. The did:key driver + document loader are built
 * here (offline P-256 did:key) and injected, so these run without network.
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {BLS_MULTIKEY_HEADER, generateBlsMultikey} from '../core/bls.js';
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

// --- bbs-2023: unlinkable disclosure (Phase 2.5) ---

/**
 * Build a BLS12-381 did:key issuer + the project's offline document loader.
 *
 * @returns {Promise<{
 *   did: string, signer: object, documentLoader: DocumentLoader
 * }>} The issuer DID, its BBS signer, and a did:key-aware loader.
 */
async function makeBlsIssuer() {
  const driver = didKeyDriverFactory();
  driver.use({
    multibaseMultikeyHeader: BLS_MULTIKEY_HEADER,
    fromMultibase: Bls12381Multikey.from
  });
  const keyPair = await generateBlsMultikey();
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

/**
 * Issue a base SD credential under the bbs-2023 cryptosuite.
 *
 * @param {{did: string, signer: object, documentLoader: DocumentLoader}} ctx
 *   The BLS issuer context.
 * @returns {Promise<Record<string, unknown>>} The signed base credential.
 */
async function issueBlsBase(ctx) {
  return issueSdCredential({
    issuerDid: ctx.did,
    subjectDid: AGENT_DID,
    claims: {birthdate: '2000-01-01', age_over_18: true, age_over_21: true},
    mandatoryPointers: MANDATORY,
    signer: ctx.signer,
    documentLoader: ctx.documentLoader,
    validFromInSeconds: -1,
    expiresInSeconds: 3600,
    cryptosuite: 'bbs-2023'
  });
}

describe('bbs-2023 selective disclosure', () => {
  it('issues a base proof with the bbs-2023 cryptosuite', async () => {
    const ctx = await makeBlsIssuer();
    const base = await issueBlsBase(ctx);
    const proof = /** @type {{cryptosuite: string}} */ (base.proof);
    expect(proof.cryptosuite).toBe('bbs-2023');
  });

  it('derives a reveal document disclosing only age_over_21', async () => {
    const ctx = await makeBlsIssuer();
    const base = await issueBlsBase(ctx);
    const revealed = await deriveDisclosure({
      credential: base,
      selectivePointers: ['/credentialSubject/age_over_21'],
      documentLoader: ctx.documentLoader,
      cryptosuite: 'bbs-2023'
    });
    const subject = /** @type {Record<string, unknown>} */ (
      revealed.credentialSubject
    );
    expect(subject.age_over_21).toBe(true);
    expect(subject.birthdate).toBeUndefined();
    expect(subject.age_over_18).toBeUndefined();
  });

  it('verifies a genuine bbs-2023 reveal document', async () => {
    const ctx = await makeBlsIssuer();
    const base = await issueBlsBase(ctx);
    const revealed = await deriveDisclosure({
      credential: base,
      selectivePointers: ['/credentialSubject/age_over_21'],
      documentLoader: ctx.documentLoader,
      cryptosuite: 'bbs-2023'
    });
    const result = await verifyDisclosure({
      revealDocument: revealed,
      documentLoader: ctx.documentLoader,
      cryptosuite: 'bbs-2023'
    });
    expect(result.valid).toBe(true);
    expect(result.revealedClaims?.age_over_21).toBe(true);
  });

  it('produces unlinkable derivations: two reveals differ yet both verify ' +
    '(R-L3-7)', async () => {
    const ctx = await makeBlsIssuer();
    const base = await issueBlsBase(ctx);
    const opts = {
      credential: base,
      selectivePointers: ['/credentialSubject/age_over_21'],
      documentLoader: ctx.documentLoader,
      cryptosuite: /** @type {'bbs-2023'} */ ('bbs-2023')
    };
    const a = await deriveDisclosure(opts);
    const b = await deriveDisclosure(opts);
    const proofA = /** @type {{proofValue: string}} */ (a.proof);
    const proofB = /** @type {{proofValue: string}} */ (b.proof);
    // unlinkable: the two derived proofs are not correlatable
    expect(proofA.proofValue).not.toEqual(proofB.proofValue);
    // ...yet both verify independently
    for(const reveal of [a, b]) {
      const result = await verifyDisclosure({
        revealDocument: reveal,
        documentLoader: ctx.documentLoader,
        cryptosuite: 'bbs-2023'
      });
      expect(result.valid).toBe(true);
    }
  });

  it('rejects a tampered bbs-2023 reveal document', async () => {
    const ctx = await makeBlsIssuer();
    const base = await issueBlsBase(ctx);
    const revealed = await deriveDisclosure({
      credential: base,
      selectivePointers: ['/credentialSubject/age_over_21'],
      documentLoader: ctx.documentLoader,
      cryptosuite: 'bbs-2023'
    });
    const tampered = JSON.parse(JSON.stringify(revealed));
    tampered.credentialSubject.age_over_21 = false;
    const result = await verifyDisclosure({
      revealDocument: tampered,
      documentLoader: ctx.documentLoader,
      cryptosuite: 'bbs-2023'
    });
    expect(result.valid).toBe(false);
  });
});
