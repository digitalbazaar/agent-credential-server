/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {jest} from '@jest/globals';

/**
 * @typedef {import("../core/resolver.js").ResolutionResult} ResolutionResult
 * @typedef {import("../core/crypto.js").KeyPair} KeyPair
 * @typedef {import("../core/vc.js").DataIntegrityCredential}
 *   DataIntegrityCredential
 */

// ESM-native mock — the issuer resolves offline via did:key, but the agent
// auth-proof path still resolves the agent DID through the Universal Resolver.
/** @type {jest.MockedFunction<(did: string) => Promise<ResolutionResult>>} */
const mockResolveDID = jest.fn();
jest.unstable_mockModule('../core/resolver.js', () => ({
  resolveDID: mockResolveDID
}));

const {generateKeyPair, toBase64url, sign} = await import('../core/crypto.js');
const {issueCredentialTool} = await import('../tools/issue.js');
const {checkDelegation} = await import('../tools/delegate.js');
const {generateChallenge, signingInput} = await import('../core/challenge.js');
const {deriveDidKeyIssuer, makeDidKeyDriver} =
  await import('../tools/didKeyContext.js');

const AGENT_DID = 'did:key:z6MkAgent';
const ACTION = 'access:age-restricted-content';

/**
 * Derive the did:key that encodes a key pair's public key.
 *
 * @param {KeyPair} kp - The key pair.
 * @returns {Promise<string>} The did:key.
 */
async function deriveDidKey(kp) {
  const {did} = await deriveDidKeyIssuer(kp.privateKey, makeDidKeyDriver());
  return did;
}

/**
 * Issue a DI credential to the agent from a freshly derived did:key issuer.
 * Returns the signed credential and the issuer's raw key for reuse.
 *
 * @param {object} [options] - Issuance options.
 * @param {Record<string, unknown>} [options.claims] - The subject claims.
 * @param {number} [options.expiresInSeconds] - TTL in seconds.
 * @param {string} [options.subjectDid] - Override the subject DID.
 * @returns {Promise<DataIntegrityCredential>} The signed credential.
 */
async function makeVC(options = {}) {
  const {
    claims = {age_verified: true, over_21: true},
    expiresInSeconds,
    subjectDid = AGENT_DID
  } = options;
  const kp = await generateKeyPair();
  return issueCredentialTool({
    subjectDid,
    claims,
    privateKeyBase64url: toBase64url(kp.privateKey),
    expiresInSeconds
  });
}

describe('checkDelegation', () => {
  beforeEach(() => jest.clearAllMocks());

  it('authorizes when VC is valid and all required claims satisfied',
    async () => {
      const credential = await makeVC();
      const result = await checkDelegation({
        agentDid: AGENT_DID,
        requestedAction: ACTION,
        credential,
        requiredClaims: {age_verified: true, over_21: true}
      });
      expect(result.authorized).toBe(true);
      expect(result.reason).toMatch(AGENT_DID);
    });

  it('authorizes with no required claims specified', async () => {
    const credential = await makeVC();
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential
    });
    expect(result.authorized).toBe(true);
  });

  it('denies when VC subject does not match agent DID', async () => {
    const credential = await makeVC();
    const result = await checkDelegation({
      agentDid: 'did:key:z6MkSomeoneElse',
      requestedAction: ACTION,
      credential
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/does not match/);
  });

  it('denies when required claim is missing from VC', async () => {
    const credential = await makeVC({claims: {age_verified: true}});
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential,
      requiredClaims: {over_21: true}
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/over_21/);
  });

  it('denies when required claim has wrong value', async () => {
    const credential = await makeVC({claims: {over_21: false}});
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential,
      requiredClaims: {over_21: true}
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/over_21/);
  });

  it('denies when VC is expired', async () => {
    // expire well beyond the 300s default clock skew
    const credential = await makeVC({
      claims: {over_21: true}, expiresInSeconds: -3600
    });
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/validUntil|expired/i);
  });

  it('denies when the credentialSubject is tampered', async () => {
    const credential = await makeVC({claims: {over_21: true}});
    // mutate a signed claim — the Data Integrity proof no longer verifies
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

  it('denies when the issuer is swapped to an unrelated DID', async () => {
    const credential = await makeVC({claims: {over_21: true}});
    // point issuer at a different did:key — the proof was made by the
    // original key, so verification against the new issuer fails
    const forged = JSON.parse(JSON.stringify(credential));
    forged.issuer = 'did:key:z6Mkjchhft5cN8Eig6FxQZBm75MEXbunk8JnvNXrNWsdBg';
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential: forged
    });
    expect(result.authorized).toBe(false);
  });
});

describe('checkDelegation: predicate claims', () => {
  beforeEach(() => jest.clearAllMocks());

  it('authorizes when predicate $gte is satisfied', async () => {
    const credential = await makeVC({claims: {age: 25}});
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential,
      requiredClaims: {age: {$gte: 21}}
    });
    expect(result.authorized).toBe(true);
  });

  it('denies when predicate $gte is not satisfied', async () => {
    const credential = await makeVC({claims: {age: 18}});
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential,
      requiredClaims: {age: {$gte: 21}}
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/age/);
  });

  it('authorizes with $in predicate', async () => {
    const credential = await makeVC({claims: {role: 'admin'}});
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      credential,
      requiredClaims: {role: {$in: ['admin', 'superuser']}}
    });
    expect(result.authorized).toBe(true);
  });
});

describe('checkDelegation: authProof', () => {
  /** @type {KeyPair} */
  let agentKp;
  /** @type {string} */
  let agentDid;

  beforeEach(async () => {
    agentKp = await generateKeyPair();
    // the agent DID is a real did:key derived from the agent key, so the auth
    // path resolves it offline to the matching public key
    agentDid = await deriveDidKey(agentKp);
    jest.clearAllMocks();
  });

  it('authorizes when authProof is valid', async () => {
    const credential = await makeVC({
      claims: {over_21: true}, subjectDid: agentDid
    });
    const token = generateChallenge(agentDid);
    const sigBytes = await sign(signingInput(token), agentKp.privateKey);
    const result = await checkDelegation({
      agentDid,
      requestedAction: ACTION,
      credential,
      authProof: {
        nonce: token.nonce,
        issuedAt: token.issuedAt,
        expiresAt: token.expiresAt,
        signatureBase64url: toBase64url(sigBytes)
      }
    });
    expect(result.authorized).toBe(true);
  });

  it('denies when authProof signature is wrong', async () => {
    const wrongKp = await generateKeyPair();
    const credential = await makeVC({
      claims: {over_21: true}, subjectDid: agentDid
    });
    const token = generateChallenge(agentDid);
    const sigBytes = await sign(signingInput(token), wrongKp.privateKey);
    const result = await checkDelegation({
      agentDid,
      requestedAction: ACTION,
      credential,
      authProof: {
        nonce: token.nonce,
        issuedAt: token.issuedAt,
        expiresAt: token.expiresAt,
        signatureBase64url: toBase64url(sigBytes)
      }
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/auth/i);
  });

  it('denies when authProof challenge is expired', async () => {
    const credential = await makeVC({
      claims: {over_21: true}, subjectDid: agentDid
    });
    const expiredToken = {
      nonce: 'n', agentDid, issuedAt: 100, expiresAt: 200
    };
    const sigBytes = await sign(signingInput(expiredToken), agentKp.privateKey);
    const result = await checkDelegation({
      agentDid,
      requestedAction: ACTION,
      credential,
      authProof: {
        nonce: expiredToken.nonce,
        issuedAt: expiredToken.issuedAt,
        expiresAt: expiredToken.expiresAt,
        signatureBase64url: toBase64url(sigBytes)
      }
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/expired|auth/i);
  });

  it('denies when a non-did:key agent DID cannot be resolved', async () => {
    mockResolveDID.mockResolvedValue({
      didDocument: null,
      didResolutionMetadata: {error: 'notFound'}
    });
    const unresolvable = 'did:web:missing.example.com';
    const credential = await makeVC({
      claims: {over_21: true}, subjectDid: unresolvable
    });
    const token = generateChallenge(unresolvable);
    const sigBytes = await sign(signingInput(token), agentKp.privateKey);
    const result = await checkDelegation({
      agentDid: unresolvable,
      requestedAction: ACTION,
      credential,
      authProof: {
        nonce: token.nonce,
        issuedAt: token.issuedAt,
        expiresAt: token.expiresAt,
        signatureBase64url: toBase64url(sigBytes)
      }
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/resolve/i);
  });
});
