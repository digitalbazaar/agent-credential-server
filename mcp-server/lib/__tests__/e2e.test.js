/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * End-to-end tests: full stack with no network calls.
 * Exercises keygen → issue → check_delegation on the Data Integrity path.
 * The issuer did:key resolves offline, so no resolver mock is needed.
 */
import {generateKeyPair, toBase64url} from '../core/crypto.js';
import {checkDelegation} from '../tools/delegate.js';
import {issueCredentialTool} from '../tools/issue.js';

const AGENT_DID = 'did:key:z6MkAgentE2E';
const ACTION = 'access:age-restricted-content';

/**
 * Issue a DI credential to a subject from a fresh did:key issuer.
 *
 * @param {object} options - Issuance options.
 * @param {string} options.subjectDid - The subject DID.
 * @param {Record<string, unknown>} options.claims - The subject claims.
 * @param {number} [options.expiresInSeconds] - TTL in seconds.
 * @returns {Promise<import('../core/vc.js').DataIntegrityCredential>} The VC.
 */
async function issueTo(options) {
  const kp = await generateKeyPair();
  return issueCredentialTool({
    subjectDid: options.subjectDid,
    claims: options.claims,
    privateKeyBase64url: toBase64url(kp.privateKey),
    expiresInSeconds: options.expiresInSeconds
  });
}

describe('E2E: full delegation flow', () => {
  it('valid VC → ACCESS GRANTED', async () => {
    const credential = await issueTo({
      subjectDid: AGENT_DID,
      claims: {age_verified: true, over_21: true},
      expiresInSeconds: 3600
    });
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential,
      requiredClaims: {age_verified: true, over_21: true}
    });
    expect(result.authorized).toBe(true);
    expect(result.reason).toMatch(AGENT_DID);
  });

  it('tampered VC → ACCESS DENIED (proof mismatch)', async () => {
    const credential = await issueTo({
      subjectDid: AGENT_DID, claims: {over_21: true}, expiresInSeconds: 3600
    });
    const tampered = JSON.parse(JSON.stringify(credential));
    tampered.credentialSubject.over_21 = false;
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential: tampered
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/verif|proof|signature/i);
  });

  it('expired VC → ACCESS DENIED (with expiry reason)', async () => {
    const credential = await issueTo({
      subjectDid: AGENT_DID, claims: {over_21: true}, expiresInSeconds: -3600
    });
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/validUntil|expired/i);
  });

  it('wrong agent presents someone else\'s VC → ACCESS DENIED', async () => {
    const realAgentDid = 'did:key:z6MkRealAgent';
    const impostor = 'did:key:z6MkImpostor';
    const credential = await issueTo({
      subjectDid: realAgentDid, claims: {over_21: true}, expiresInSeconds: 3600
    });
    const result = await checkDelegation({
      agentDid: impostor,
      requestedAction: ACTION,
      credential
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/does not match/);
  });
});
