/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { jest } from "@jest/globals";

/**
 * @typedef {import("../core/resolver.js").ResolutionResult} ResolutionResult
 * @typedef {import("../core/crypto.js").KeyPair} KeyPair
 */

// ESM-native mock — must be called before dynamic imports
/** @type {jest.MockedFunction<(did: string) => Promise<ResolutionResult>>} */
const mockResolveDID = jest.fn();
jest.unstable_mockModule("../core/resolver.js", () => ({
  resolveDID: mockResolveDID,
}));

// Dynamic imports after mock registration
const { generateKeyPair, toBase64url, sign } = await import("../core/crypto.js");
const { issueCredential } = await import("../core/vc.js");
const { checkDelegation } = await import("../tools/delegate.js");
const { generateChallenge, signingInput } = await import("../core/challenge.js");

const ISSUER_DID = "did:key:z6MkHuman";
const AGENT_DID = "did:key:z6MkAgent";
const ACTION = "access:age-restricted-content";

/**
 * @param {KeyPair} kp
 * @param {Record<string, unknown>} [claims]
 * @param {number} [expiresInSeconds]
 */
async function makeVC(kp, claims = { age_verified: true, over_21: true }, expiresInSeconds) {
  return issueCredential(AGENT_DID, claims, ISSUER_DID, kp, expiresInSeconds);
}

/**
 * @param {KeyPair} kp
 */
function mockResolver(kp) {
  const resolution = {
    didDocument: {
      id: ISSUER_DID,
      verificationMethod: [
        {
          id: `${ISSUER_DID}#key-1`,
          type: "JsonWebKey2020",
          controller: ISSUER_DID,
          publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: toBase64url(kp.publicKey) },
        },
      ],
    },
    didResolutionMetadata: {},
  };
  mockResolveDID.mockResolvedValue(resolution);
}

describe("checkDelegation", () => {
  /** @type {KeyPair} */
  let kp;

  beforeEach(async () => {
    kp = await generateKeyPair();
    jest.clearAllMocks();
  });

  it("authorizes when VC is valid and all required claims satisfied", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      requiredClaims: { age_verified: true, over_21: true },
    });
    expect(result.authorized).toBe(true);
    expect(result.reason).toMatch(AGENT_DID);
  });

  it("authorizes with no required claims specified", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(true);
  });

  it("denies when VC subject does not match agent DID", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: "did:key:z6MkSomeoneElse",
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/does not match/);
  });

  it("denies when required claim is missing from VC", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { age_verified: true }); // no over_21
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      requiredClaims: { over_21: true },
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/over_21/);
  });

  it("denies when required claim has wrong value", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { over_21: false });
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      requiredClaims: { over_21: true },
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/over_21/);
  });

  it("denies when VC is expired", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { over_21: true }, -1);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  it("denies when VC payload is tampered", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { over_21: true });
    const parts = vc.jwt.split(".");
    const fakeBody = Buffer.from(
      JSON.stringify({ iss: ISSUER_DID, sub: AGENT_DID, iat: 0, vc: { credentialSubject: { id: AGENT_DID, over_21: false } } })
    ).toString("base64url");
    const tampered = `${parts[0]}.${fakeBody}.${parts[2]}`;
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: tampered,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it("denies when DID resolution fails", async () => {
    mockResolveDID.mockResolvedValue({
      didDocument: null,
      didResolutionMetadata: { error: "notFound" },
    });
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/resolve/i);
  });

  it("denies when DID document has no Ed25519 key", async () => {
    mockResolveDID.mockResolvedValue({
      didDocument: {
        id: ISSUER_DID,
        verificationMethod: [
          {
            id: `${ISSUER_DID}#key-1`,
            type: "RsaVerificationKey2018",
            controller: ISSUER_DID,
            publicKeyBase58: "someRsaKey",
          },
        ],
      },
      didResolutionMetadata: {},
    });
    const vc = await makeVC(kp);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/Ed25519/);
  });

  it("denies malformed JWT", async () => {
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: "not.a.valid.jwt.extra",
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/malformed/i);
  });
});

describe("checkDelegation: predicate claims", () => {
  /** @type {KeyPair} */
  let kp;

  beforeEach(async () => {
    kp = await generateKeyPair();
    jest.clearAllMocks();
  });

  it("authorizes when predicate $gte is satisfied", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { age: 25 });
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      requiredClaims: { age: { $gte: 21 } },
    });
    expect(result.authorized).toBe(true);
  });

  it("denies when predicate $gte is not satisfied", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { age: 18 });
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      requiredClaims: { age: { $gte: 21 } },
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/age/);
  });

  it("authorizes with $in predicate", async () => {
    mockResolver(kp);
    const vc = await makeVC(kp, { role: "admin" });
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      requiredClaims: { role: { $in: ["admin", "superuser"] } },
    });
    expect(result.authorized).toBe(true);
  });
});

describe("checkDelegation: authProof", () => {
  /** @type {KeyPair} */
  let issuerKp;
  /** @type {KeyPair} */
  let agentKp;

  beforeEach(async () => {
    issuerKp = await generateKeyPair();
    agentKp = await generateKeyPair();
    jest.clearAllMocks();
  });

  /**
   * @param {Record<string, KeyPair>} didToKey
   */
  function mockResolverForDids(didToKey) {
    mockResolveDID.mockImplementation(async (/** @type {string} */ did) => {
      const kp = didToKey[did];
      if (!kp) return { didDocument: null, didResolutionMetadata: { error: "notFound" } };
      return {
        didDocument: {
          id: did,
          verificationMethod: [{ id: `${did}#key-1`, type: "JsonWebKey2020", controller: did, publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: toBase64url(kp.publicKey) } }],
        },
        didResolutionMetadata: {},
      };
    });
  }

  it("authorizes when authProof is valid", async () => {
    mockResolverForDids({ [ISSUER_DID]: issuerKp, [AGENT_DID]: agentKp });
    const vc = await issueCredential(AGENT_DID, { over_21: true }, ISSUER_DID, issuerKp, 3600);
    const token = generateChallenge(AGENT_DID);
    const sigBytes = await sign(signingInput(token), agentKp.privateKey);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      authProof: { nonce: token.nonce, issuedAt: token.issuedAt, expiresAt: token.expiresAt, signatureBase64url: toBase64url(sigBytes) },
    });
    expect(result.authorized).toBe(true);
  });

  it("denies when authProof signature is wrong", async () => {
    const wrongKp = await generateKeyPair();
    mockResolverForDids({ [ISSUER_DID]: issuerKp, [AGENT_DID]: agentKp });
    const vc = await issueCredential(AGENT_DID, { over_21: true }, ISSUER_DID, issuerKp, 3600);
    const token = generateChallenge(AGENT_DID);
    const sigBytes = await sign(signingInput(token), wrongKp.privateKey); // wrong key
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      authProof: { nonce: token.nonce, issuedAt: token.issuedAt, expiresAt: token.expiresAt, signatureBase64url: toBase64url(sigBytes) },
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/auth/i);
  });

  it("denies when authProof challenge is expired", async () => {
    mockResolverForDids({ [ISSUER_DID]: issuerKp, [AGENT_DID]: agentKp });
    const vc = await issueCredential(AGENT_DID, { over_21: true }, ISSUER_DID, issuerKp, 3600);
    const expiredToken = { nonce: "n", agentDid: AGENT_DID, issuedAt: 100, expiresAt: 200 };
    const sigBytes = await sign(signingInput(expiredToken), agentKp.privateKey);
    const result = await checkDelegation({
      agentDid: AGENT_DID,
      requestedAction: ACTION,
      vcJwt: vc.jwt,
      authProof: { nonce: expiredToken.nonce, issuedAt: expiredToken.issuedAt, expiresAt: expiredToken.expiresAt, signatureBase64url: toBase64url(sigBytes) },
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/expired|auth/i);
  });
});
