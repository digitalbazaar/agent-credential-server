/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Tool-layer tests for the selective-disclosure path: issue an SD credential
 * from a P-256 key, derive a disclosure, and verify it — through the MCP tool
 * functions, which wire the did:key/ECDSA IO seam to the pure vcSd core. All
 * offline (did:key).
 */
import {deriveDisclosureTool} from '../tools/deriveDisclosure.js';
import {generateEcdsaMultikey} from '../core/ecdsa.js';
import {issueSdCredentialTool} from '../tools/issueSd.js';
import {verifyDisclosureTool} from '../tools/verifyDisclosure.js';

const AGENT_DID = 'did:example:agent';

/**
 * Issue a base SD credential to the agent from a fresh P-256 issuer key.
 *
 * @param {object} [overrides] - Optional issue-input overrides.
 * @returns {Promise<Record<string, unknown>>} The signed base credential.
 */
async function issueBase(overrides = {}) {
  const key = await generateEcdsaMultikey();
  const exported = /** @type {{
   *   publicKeyMultibase: string, secretKeyMultibase: string
   * }} */ (await key.export({publicKey: true, secretKey: true}));
  const {publicKeyMultibase, secretKeyMultibase} = exported;
  return issueSdCredentialTool({
    subjectDid: AGENT_DID,
    claims: {
      birthdate: '2000-01-01',
      age_over_18: true,
      age_over_21: true,
      age_over_65: false,
      name: 'Pat Holder'
    },
    publicKeyMultibase,
    privateKeyMultibase: secretKeyMultibase,
    expiresInSeconds: 3600,
    ...overrides
  });
}

describe('issueSdCredentialTool', () => {
  it('issues a base proof and derives the issuer did:key from the key',
    async () => {
      const base = await issueBase();
      const proof = /** @type {{cryptosuite: string}} */ (base.proof);
      expect(proof.cryptosuite).toBe('ecdsa-sd-2023');
      expect(String(base.issuer)).toMatch(/^did:key:zDna/);
    });
});

describe('deriveDisclosureTool', () => {
  it('reveals only the requested flag, hiding the rest', async () => {
    const base = await issueBase();
    const revealed = await deriveDisclosureTool({
      credential: base, revealClaims: ['age_over_21']
    });
    const subject = /** @type {Record<string, unknown>} */ (
      revealed.credentialSubject
    );
    expect(subject.age_over_21).toBe(true);
    expect(subject.birthdate).toBeUndefined();
    expect(subject.name).toBeUndefined();
    expect(subject.age_over_18).toBeUndefined();
  });

  it('rejects a request for more than two age_over_NN flags (R-L3-6)',
    async () => {
      const base = await issueBase();
      await expect(deriveDisclosureTool({
        credential: base,
        revealClaims: ['age_over_18', 'age_over_21', 'age_over_65']
      })).rejects.toThrow(/two|age_over/i);
    });
});

describe('verifyDisclosureTool', () => {
  it('verifies a genuine reveal document end-to-end', async () => {
    const base = await issueBase();
    const revealed = await deriveDisclosureTool({
      credential: base, revealClaims: ['age_over_21']
    });
    const result = await verifyDisclosureTool({revealDocument: revealed});
    expect(result.valid).toBe(true);
    expect(String(result.issuer)).toMatch(/^did:key:zDna/);
    const claims = result.revealedClaims ?? {};
    expect(claims.age_over_21).toBe(true);
  });

  it('denies a tampered reveal document', async () => {
    const base = await issueBase();
    const revealed = await deriveDisclosureTool({
      credential: base, revealClaims: ['age_over_21']
    });
    const tampered = JSON.parse(JSON.stringify(revealed));
    tampered.credentialSubject.age_over_21 = false;
    const result = await verifyDisclosureTool({revealDocument: tampered});
    expect(result.valid).toBe(false);
    expect(result.reason).toEqual(expect.any(String));
  });
});
