/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * End-to-end tests: full stack with no network calls.
 * Exercises keygen → issue → check_delegation in one flow.
 * Uses unstable_mockModule for ESM-compatible mocking.
 */
import { jest } from "@jest/globals";

/** @typedef {import("../core/resolver.js").ResolutionResult} ResolutionResult */

/** @type {jest.MockedFunction<() => Promise<ResolutionResult>>} */
const mockResolveDID = jest.fn();
jest.unstable_mockModule("../core/resolver.js", () => ({
  resolveDID: mockResolveDID,
}));

const { generateKeyPair, toBase64url } = await import("../core/crypto.js");
const { issueCredential } = await import("../core/vc.js");
const { checkDelegation } = await import("../tools/delegate.js");

describe("E2E: full delegation flow", () => {
  beforeEach(() => jest.clearAllMocks());

  it("valid VC → ACCESS GRANTED", async () => {
    const humanKeyPair = await generateKeyPair();
    const humanDid = "did:key:z6MkHumanE2E";
    const agentDid = "did:key:z6MkAgentE2E";

    const vc = await issueCredential(
      agentDid,
      { age_verified: true, over_21: true },
      humanDid,
      humanKeyPair,
      3600
    );

    mockResolveDID.mockResolvedValue({
      didDocument: {
        id: humanDid,
        verificationMethod: [{
          id: `${humanDid}#key-1`,
          type: "JsonWebKey2020",
          controller: humanDid,
          publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: toBase64url(humanKeyPair.publicKey) },
        }],
      },
      didResolutionMetadata: {},
    });

    const result = await checkDelegation({
      agentDid,
      requestedAction: "access:age-restricted-content",
      vcJwt: vc.jwt,
      requiredClaims: { age_verified: true, over_21: true },
    });

    expect(result.authorized).toBe(true);
    expect(result.reason).toMatch(agentDid);
  });

  it("tampered VC → ACCESS DENIED (signature mismatch)", async () => {
    const humanKeyPair = await generateKeyPair();
    const humanDid = "did:key:z6MkHumanTamper";
    const agentDid = "did:key:z6MkAgentTamper";

    const vc = await issueCredential(agentDid, { over_21: true }, humanDid, humanKeyPair, 3600);

    const parts = vc.jwt.split(".");
    const fakeBody = Buffer.from(
      JSON.stringify({ iss: humanDid, sub: agentDid, iat: 0, exp: 9999999999, vc: { credentialSubject: { id: agentDid, over_21: false } } })
    ).toString("base64url");
    const tampered = `${parts[0]}.${fakeBody}.${parts[2]}`;

    mockResolveDID.mockResolvedValue({
      didDocument: {
        id: humanDid,
        verificationMethod: [{
          id: `${humanDid}#key-1`,
          type: "JsonWebKey2020",
          controller: humanDid,
          publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: toBase64url(humanKeyPair.publicKey) },
        }],
      },
      didResolutionMetadata: {},
    });

    const result = await checkDelegation({
      agentDid,
      requestedAction: "access:age-restricted-content",
      vcJwt: tampered,
    });

    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it("expired VC → ACCESS DENIED (with expiry reason)", async () => {
    const humanKeyPair = await generateKeyPair();
    const humanDid = "did:key:z6MkHumanExpired";
    const agentDid = "did:key:z6MkAgentExpired";

    const vc = await issueCredential(agentDid, { over_21: true }, humanDid, humanKeyPair, -1);

    mockResolveDID.mockResolvedValue({
      didDocument: {
        id: humanDid,
        verificationMethod: [{
          id: `${humanDid}#key-1`,
          type: "JsonWebKey2020",
          controller: humanDid,
          publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: toBase64url(humanKeyPair.publicKey) },
        }],
      },
      didResolutionMetadata: {},
    });

    const result = await checkDelegation({
      agentDid,
      requestedAction: "access:age-restricted-content",
      vcJwt: vc.jwt,
    });

    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  it("wrong agent presents someone else's VC → ACCESS DENIED", async () => {
    const humanKeyPair = await generateKeyPair();
    const humanDid = "did:key:z6MkHumanWrong";
    const realAgentDid = "did:key:z6MkRealAgent";
    const impostor = "did:key:z6MkImpostor";

    const vc = await issueCredential(realAgentDid, { over_21: true }, humanDid, humanKeyPair, 3600);

    mockResolveDID.mockResolvedValue({
      didDocument: { id: humanDid, verificationMethod: [] },
      didResolutionMetadata: {},
    });

    const result = await checkDelegation({
      agentDid: impostor,
      requestedAction: "access:age-restricted-content",
      vcJwt: vc.jwt,
    });

    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/does not match/);
  });
});
