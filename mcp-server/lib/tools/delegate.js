/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { parseCredential, verifyCredentialJwt } from "../core/vc.js";
import { resolveDID } from "../core/resolver.js";
import { extractEd25519Key } from "./verify.js";
import { checkClaims } from "../core/claimPredicates.js";
import { fetchStatusList } from "../core/statusListFetcher.js";
import { checkRevocationStatus } from "../core/revocation.js";
import { verifyChallengeResponse } from "../core/challenge.js";

/**
 * @typedef {import("../core/claimPredicates.js").ClaimPredicate} ClaimPredicate
 * @typedef {import("../core/challenge.js").ChallengeToken} ChallengeToken
 */

/**
 * @typedef {object} DelegationResult
 * @property {boolean} authorized
 * @property {string} reason
 */

/**
 * @typedef {object} AuthProof
 * @property {string} nonce
 * @property {number} issuedAt
 * @property {number} expiresAt
 * @property {string} signatureBase64url
 */

/**
 * @typedef {object} CheckDelegationInput
 * @property {string} agentDid
 * @property {string} requestedAction
 * @property {string} vcJwt JWT-format VC
 * @property {Record<string, ClaimPredicate>} [requiredClaims] Claims that must be present and satisfy predicates for authorization
 * @property {AuthProof} [authProof] Optional agent authentication proof
 * @property {string} [expectedAudience] Optional expected audience for the VC
 */

/**
 * @param {CheckDelegationInput} input
 * @returns {Promise<DelegationResult>}
 */
export async function checkDelegation(input) {
  const { agentDid, requestedAction, vcJwt, requiredClaims = {}, authProof, expectedAudience } = input;

  // 0. Verify agent auth proof if provided
  if (authProof) {
    const agentResolution = await resolveDID(agentDid);
    if (agentResolution.didResolutionMetadata.error || !agentResolution.didDocument) {
      return {
        authorized: false,
        reason: `Cannot resolve agent DID for auth: ${agentResolution.didResolutionMetadata.error}`,
      };
    }
    const agentKey = extractEd25519Key(agentResolution.didDocument.verificationMethod ?? []);
    if (!agentKey) {
      return { authorized: false, reason: "No Ed25519 key found in agent DID document" };
    }
    /** @type {ChallengeToken} */
    const token = {
      nonce: authProof.nonce,
      agentDid,
      issuedAt: authProof.issuedAt,
      expiresAt: authProof.expiresAt,
    };
    const authResult = await verifyChallengeResponse(token, authProof.signatureBase64url, agentKey);
    if (!authResult.valid) {
      return { authorized: false, reason: `Agent authentication failed: ${authResult.reason}` };
    }
  }

  // 1. Parse the VC
  const payload = parseCredential(vcJwt);
  if (!payload) {
    return { authorized: false, reason: "Malformed VC JWT" };
  }

  // 2. Check the VC is addressed to this agent
  if (payload.sub !== agentDid) {
    return {
      authorized: false,
      reason: `VC subject (${payload.sub}) does not match agent DID (${agentDid})`,
    };
  }

  // 3. Resolve the issuer DID
  const resolution = await resolveDID(payload.iss);
  if (resolution.didResolutionMetadata.error || !resolution.didDocument) {
    return {
      authorized: false,
      reason: `Cannot resolve issuer DID: ${resolution.didResolutionMetadata.error}`,
    };
  }

  // 4. Extract public key + verify signature + check expiry + check audience
  const publicKey = extractEd25519Key(
    resolution.didDocument.verificationMethod ?? []
  );
  if (!publicKey) {
    return {
      authorized: false,
      reason: "No Ed25519 key found in issuer DID document",
    };
  }

  const verifyResult = await verifyCredentialJwt(vcJwt, publicKey, expectedAudience);
  if (!verifyResult.valid) {
    return { authorized: false, reason: verifyResult.reason ?? "Invalid VC" };
  }

  // 4.5. Check revocation status if credentialStatus is present
  if (payload.vc.credentialStatus) {
    const cs = payload.vc.credentialStatus;
    const { encodedList, error } = await fetchStatusList(cs.statusListCredential);
    if (error || !encodedList) {
      return { authorized: false, reason: `Cannot fetch status list: ${error}` };
    }
    const revocationResult = checkRevocationStatus(encodedList, cs.statusListIndex);
    if (revocationResult.revoked) {
      return { authorized: false, reason: revocationResult.reason ?? "Credential revoked" };
    }
  }

  // 5. Check required claims with predicate support
  const credentialSubject = payload.vc.credentialSubject;
  const claimsResult = checkClaims(credentialSubject, requiredClaims);
  if (!claimsResult.satisfied) {
    return { authorized: false, reason: claimsResult.reason };
  }

  return {
    authorized: true,
    reason: `Agent ${agentDid} authorized for action '${requestedAction}' by issuer ${payload.iss}`,
  };
}
