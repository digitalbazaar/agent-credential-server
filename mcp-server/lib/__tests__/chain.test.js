/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { verifyDelegationChain, extractDelegatedFrom } from "../core/chain.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { toBase64url } from "../core/crypto.js";

const { generateKeyPair } = await import("../core/crypto.js");
const { issueCredential } = await import("../core/vc.js");

const ROOT_DID = "did:key:z6MkRoot";
const MID_DID = "did:key:z6MkMid";
const LEAF_DID = "did:key:z6MkLeaf";

/**
 * @param {string} input
 * @returns {string}
 */
function sha256base64url(input) {
  return toBase64url(sha256(new TextEncoder().encode(input)));
}

async function make2HopChain() {
  const rootKp = await generateKeyPair();
  const midKp = await generateKeyPair();

  // root → mid
  const rootVc = await issueCredential(MID_DID, { delegatedFrom: null }, ROOT_DID, rootKp, 3600);

  // mid → leaf (delegatedFrom = sha256 of rootVc.jwt)
  const delegatedFrom = sha256base64url(rootVc.jwt);
  const midVc = await issueCredential(LEAF_DID, { delegatedFrom }, MID_DID, midKp, 3600);

  return { rootKp, midKp, rootVc, midVc };
}

describe("extractDelegatedFrom", () => {
  it("returns null when no delegatedFrom in payload", async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(LEAF_DID, {}, ROOT_DID, kp);
    const { parseCredential } = await import("../core/vc.js");
    const payload = parseCredential(vc.jwt);
    expect(payload).not.toBeNull();
    expect(extractDelegatedFrom(/** @type {NonNullable<typeof payload>} */ (payload))).toBeNull();
  });

  it("returns the delegatedFrom value", async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(LEAF_DID, { delegatedFrom: "abc123" }, ROOT_DID, kp);
    const { parseCredential } = await import("../core/vc.js");
    const payload = parseCredential(vc.jwt);
    expect(payload).not.toBeNull();
    expect(extractDelegatedFrom(/** @type {NonNullable<typeof payload>} */ (payload))).toBe("abc123");
  });
});

describe("verifyDelegationChain", () => {
  it("succeeds for a 2-hop chain", async () => {
    const { rootKp, midKp, rootVc, midVc } = await make2HopChain();
    const result = await verifyDelegationChain(
      [{ vcJwt: rootVc.jwt, issuerPublicKey: rootKp.publicKey }, { vcJwt: midVc.jwt, issuerPublicKey: midKp.publicKey }],
      LEAF_DID
    );
    expect(result.valid).toBe(true);
    expect(result.depth).toBe(2);
    expect(result.chain).toHaveLength(2);
  });

  it("succeeds for a 3-hop chain", async () => {
    const rootKp = await generateKeyPair();
    const midKp = await generateKeyPair();
    const mid2Kp = await generateKeyPair();
    const MID2_DID = "did:key:z6MkMid2";

    const rootVc = await issueCredential(MID_DID, {}, ROOT_DID, rootKp, 3600);
    const delegatedFrom1 = sha256base64url(rootVc.jwt);
    const midVc = await issueCredential(MID2_DID, { delegatedFrom: delegatedFrom1 }, MID_DID, midKp, 3600);
    const delegatedFrom2 = sha256base64url(midVc.jwt);
    const mid2Vc = await issueCredential(LEAF_DID, { delegatedFrom: delegatedFrom2 }, MID2_DID, mid2Kp, 3600);

    const result = await verifyDelegationChain(
      [
        { vcJwt: rootVc.jwt, issuerPublicKey: rootKp.publicKey },
        { vcJwt: midVc.jwt, issuerPublicKey: midKp.publicKey },
        { vcJwt: mid2Vc.jwt, issuerPublicKey: mid2Kp.publicKey },
      ],
      LEAF_DID
    );
    expect(result.valid).toBe(true);
    expect(result.depth).toBe(3);
  });

  it("fails when issuer doesn't match prior subject", async () => {
    const rootKp = await generateKeyPair();
    const wrongIssuerKp = await generateKeyPair();
    const WRONG_ISSUER_DID = "did:key:z6MkWrongIssuer";

    const rootVc = await issueCredential(MID_DID, {}, ROOT_DID, rootKp, 3600);
    // This VC is issued by WRONG_ISSUER_DID (should be issued by MID_DID to continue the chain)
    const wrongVc = await issueCredential(LEAF_DID, {}, WRONG_ISSUER_DID, wrongIssuerKp, 3600);

    const result = await verifyDelegationChain(
      [{ vcJwt: rootVc.jwt, issuerPublicKey: rootKp.publicKey }, { vcJwt: wrongVc.jwt, issuerPublicKey: wrongIssuerKp.publicKey }],
      LEAF_DID
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/issuer/i);
  });

  it("fails on invalid signature in chain", async () => {
    const { rootKp, midKp, rootVc, midVc } = await make2HopChain();
    const wrongKp = await generateKeyPair();
    const result = await verifyDelegationChain(
      [{ vcJwt: rootVc.jwt, issuerPublicKey: wrongKp.publicKey }, { vcJwt: midVc.jwt, issuerPublicKey: midKp.publicKey }],
      LEAF_DID
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it("fails when expired link in chain", async () => {
    const rootKp = await generateKeyPair();
    const midKp = await generateKeyPair();

    const rootVc = await issueCredential(MID_DID, {}, ROOT_DID, rootKp, -1); // expired
    const delegatedFrom = sha256base64url(rootVc.jwt);
    const midVc = await issueCredential(LEAF_DID, { delegatedFrom }, MID_DID, midKp, 3600);

    const result = await verifyDelegationChain(
      [{ vcJwt: rootVc.jwt, issuerPublicKey: rootKp.publicKey }, { vcJwt: midVc.jwt, issuerPublicKey: midKp.publicKey }],
      LEAF_DID
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  it("fails when max depth exceeded", async () => {
    const rootKp = await generateKeyPair();
    const midKp = await generateKeyPair();
    const { rootVc, midVc } = await make2HopChain();

    const result = await verifyDelegationChain(
      [{ vcJwt: rootVc.jwt, issuerPublicKey: rootKp.publicKey }, { vcJwt: midVc.jwt, issuerPublicKey: midKp.publicKey }],
      LEAF_DID,
      1 // max depth = 1
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/depth/i);
  });

  it("fails when leaf subject doesn't match agentDid", async () => {
    const { rootKp, midKp, rootVc, midVc } = await make2HopChain();
    const result = await verifyDelegationChain(
      [{ vcJwt: rootVc.jwt, issuerPublicKey: rootKp.publicKey }, { vcJwt: midVc.jwt, issuerPublicKey: midKp.publicKey }],
      "did:key:z6MkSomeoneElse"
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/leaf/i);
  });

  it("fails for empty chain", async () => {
    const result = await verifyDelegationChain([], LEAF_DID);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/empty/i);
  });

  it("detects circular reference via seen-issuer set", async () => {
    const rootKp = await generateKeyPair();
    // Two VCs both issued by ROOT_DID
    const vc1 = await issueCredential(MID_DID, {}, ROOT_DID, rootKp, 3600);
    const vc2 = await issueCredential(LEAF_DID, {}, ROOT_DID, rootKp, 3600);

    const result = await verifyDelegationChain(
      [{ vcJwt: vc1.jwt, issuerPublicKey: rootKp.publicKey }, { vcJwt: vc2.jwt, issuerPublicKey: rootKp.publicKey }],
      LEAF_DID
    );
    // vc2's issuer (ROOT_DID) was already seen as vc1's issuer — circular
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/issuer.*already seen|circular/i);
  });
});
