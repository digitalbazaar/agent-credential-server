/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { jest } from "@jest/globals";

/**
 * @typedef {import("../core/resolver.js").ResolutionResult} ResolutionResult
 * @typedef {import("../core/crypto.js").KeyPair} KeyPair
 */

/** @type {jest.MockedFunction<(did: string) => Promise<ResolutionResult>>} */
const mockResolveDID = jest.fn();
jest.unstable_mockModule("../core/resolver.js", () => ({
  resolveDID: mockResolveDID,
}));

const { generateKeyPair, toBase64url } = await import("../core/crypto.js");
const { issueCredential } = await import("../core/vc.js");
const { verifyDelegationChainTool } = await import("../tools/verifyChain.js");

const ROOT_DID = "did:key:z6MkRoot";
const MID_DID = "did:key:z6MkMid";
const LEAF_DID = "did:key:z6MkLeaf";

/**
 * @param {string} did
 * @param {KeyPair} kp
 * @returns {ResolutionResult}
 */
function mockDIDWithKey(did, kp) {
  return {
    didDocument: {
      id: did,
      verificationMethod: [
        {
          id: `${did}#key-1`,
          type: "JsonWebKey2020",
          controller: did,
          publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: toBase64url(kp.publicKey) },
        },
      ],
    },
    didResolutionMetadata: {},
  };
}

describe("verifyDelegationChainTool", () => {
  /** @type {KeyPair} */
  let rootKp;
  /** @type {KeyPair} */
  let midKp;

  beforeEach(async () => {
    rootKp = await generateKeyPair();
    midKp = await generateKeyPair();
    jest.clearAllMocks();
  });

  it("authorizes a valid 2-hop chain", async () => {
    const rootVc = await issueCredential(MID_DID, {}, ROOT_DID, rootKp, 3600);
    const midVc = await issueCredential(LEAF_DID, {}, MID_DID, midKp, 3600);

    mockResolveDID.mockImplementation(async (did) => {
      if (did === ROOT_DID) return mockDIDWithKey(ROOT_DID, rootKp);
      if (did === MID_DID) return mockDIDWithKey(MID_DID, midKp);
      return { didDocument: null, didResolutionMetadata: { error: "notFound" } };
    });

    const result = await verifyDelegationChainTool({
      vcChain: [rootVc.jwt, midVc.jwt],
      agentDid: LEAF_DID,
    });
    expect(result.authorized).toBe(true);
    expect(result.depth).toBe(2);
    expect(result.chain).toHaveLength(2);
  });

  it("rejects when DID resolution fails", async () => {
    const rootVc = await issueCredential(MID_DID, {}, ROOT_DID, rootKp, 3600);

    mockResolveDID.mockResolvedValue({
      didDocument: null,
      didResolutionMetadata: { error: "notFound" },
    });

    const result = await verifyDelegationChainTool({
      vcChain: [rootVc.jwt],
      agentDid: MID_DID,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/resolve/i);
  });

  it("rejects malformed JWT in chain", async () => {
    mockResolveDID.mockResolvedValue({
      didDocument: null,
      didResolutionMetadata: {},
    });

    const result = await verifyDelegationChainTool({
      vcChain: ["not.a.valid.jwt.extra"],
      agentDid: LEAF_DID,
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/malformed/i);
  });

  it("rejects empty chain", async () => {
    const result = await verifyDelegationChainTool({ vcChain: [], agentDid: LEAF_DID });
    expect(result.authorized).toBe(false);
  });

  it("rejects broken chain (issuer != prior subject)", async () => {
    // Both issued by ROOT_DID — second should be issued by MID_DID
    const rootVc = await issueCredential(MID_DID, {}, ROOT_DID, rootKp, 3600);
    const wrongVc = await issueCredential(LEAF_DID, {}, ROOT_DID, rootKp, 3600);

    mockResolveDID.mockImplementation(async (did) => {
      if (did === ROOT_DID) return mockDIDWithKey(ROOT_DID, rootKp);
      return { didDocument: null, didResolutionMetadata: { error: "notFound" } };
    });

    const result = await verifyDelegationChainTool({
      vcChain: [rootVc.jwt, wrongVc.jwt],
      agentDid: LEAF_DID,
    });
    expect(result.authorized).toBe(false);
  });
});
