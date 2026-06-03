/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {makeDocumentLoader, resolveAgentKey} from './didKeyContext.js';
import {checkClaims} from '../core/claimPredicates.js';
import {checkRevocationStatus} from '../core/revocation.js';
import {fetchStatusList} from '../core/statusListFetcher.js';
import {verifyChallengeResponse} from '../core/challenge.js';
import {verifyCredentialDI} from '../core/vc.js';

/**
 * @typedef {import("../core/claimPredicates.js").ClaimPredicate} ClaimPredicate
 * @typedef {import("../core/challenge.js").ChallengeToken} ChallengeToken
 * @typedef {import("../core/vc.js").DataIntegrityCredential}
 *   DataIntegrityCredential
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
 * @property {DataIntegrityCredential} credential The VC 2.0 credential.
 * @property {Record<string, ClaimPredicate>} [requiredClaims] Claims that
 *   must be present and satisfy predicates for authorization.
 * @property {AuthProof} [authProof] Optional agent authentication proof.
 */

/**
 * Verify that an agent's VC authorizes a specific requested action.
 *
 * @param {CheckDelegationInput} input - Agent DID, action, VC, and optional
 *   required claims and auth proof.
 * @returns {Promise<DelegationResult>} Whether the action is authorized.
 */
export async function checkDelegation(input) {
  const {
    agentDid, requestedAction, credential, requiredClaims = {}, authProof
  } = input;

  // 0. Verify agent auth proof if provided.
  // KYA-OS R-L1-5, R-L1-6: authenticate control of the agent DID via a signed
  // nonce challenge; reject an expired or wrongly-signed proof.
  if(authProof) {
    const agentKey = await resolveAgentKey(agentDid);
    if(!agentKey) {
      return {
        authorized: false,
        reason: `Cannot resolve agent DID for auth: ${agentDid}`
      };
    }
    /** @type {ChallengeToken} */
    const token = {
      nonce: authProof.nonce,
      agentDid,
      issuedAt: authProof.issuedAt,
      expiresAt: authProof.expiresAt
    };
    const authResult = await verifyChallengeResponse(
      token,
      authProof.signatureBase64url,
      agentKey
    );
    if(!authResult.valid) {
      return {
        authorized: false,
        reason: `Agent authentication failed: ${authResult.reason}`
      };
    }
  }

  // 1. Check the VC is addressed to this agent.
  // KYA-OS R-L2-2: bind the credential to the requesting agent
  // (credentialSubject.id MUST equal the agent DID).
  if(credential.credentialSubject.id !== agentDid) {
    return {
      authorized: false,
      reason: `VC subject (${credential.credentialSubject.id}) does not ` +
        `match agent DID (${agentDid})`
    };
  }

  // 2. Verify the proof, issuer, and expiry via Data Integrity. Resolution
  //    happens inside the loader (offline for did:key issuers).
  // KYA-OS R-L2-3, R-L2-4, R-L2-5, R-L2-6: the proof MUST verify against the
  // resolved issuer DID, and an expired (validUntil) or not-yet-valid
  // (validFrom) credential MUST be denied.
  const verifyResult = await verifyCredentialDI({
    credential,
    documentLoader: makeDocumentLoader()
  });
  if(!verifyResult.valid) {
    return {authorized: false, reason: verifyResult.reason ?? 'Invalid VC'};
  }

  // 3. Check revocation status if credentialStatus is present.
  // KYA-OS R-L2-7: per-request revocation check; a revoked credential is
  // denied.
  if(credential.credentialStatus) {
    const cs = credential.credentialStatus;
    const {encodedList, error} = await fetchStatusList(cs.statusListCredential);
    if(error || !encodedList) {
      return {authorized: false, reason: `Cannot fetch status list: ${error}`};
    }
    const revocationResult = await checkRevocationStatus(
      encodedList,
      cs.statusListIndex
    );
    if(revocationResult.revoked) {
      return {
        authorized: false,
        reason: revocationResult.reason ?? 'Credential revoked'
      };
    }
  }

  // 4. Check required claims with predicate support.
  // KYA-OS R-L2-9: scoped authorization — the requested action MUST satisfy
  // the credential's permitted claims/scope.
  const claimsResult = checkClaims(
    credential.credentialSubject, requiredClaims
  );
  if(!claimsResult.satisfied) {
    return {authorized: false, reason: claimsResult.reason};
  }

  return {
    authorized: true,
    reason: `Agent ${agentDid} authorized for action '${requestedAction}' ` +
      `by issuer ${credential.issuer}`
  };
}
