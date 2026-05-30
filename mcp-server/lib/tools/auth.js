/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * IO boundary for agent authentication tools.
 */
import {generateChallenge, verifyChallengeResponse} from '../core/challenge.js';
import {extractEd25519Key} from './verify.js';
import {resolveDID} from '../core/resolver.js';

/**
 * @typedef {import("../core/challenge.js").ChallengeToken} ChallengeToken
 */

/**
 * Generate an authentication challenge for an agent to sign.
 *
 * @param {{agentDid: string, ttlSeconds?: number}} input - Agent DID and
 *   optional challenge TTL in seconds.
 * @returns {Promise<ChallengeToken>} The generated challenge token.
 */
export async function createChallengeTool(input) {
  return generateChallenge(input.agentDid, input.ttlSeconds);
}

/**
 * Verify an agent's signed challenge response to authenticate the agent.
 *
 * @param {{
 *   agentDid: string,
 *   nonce: string,
 *   issuedAt: number,
 *   signatureBase64url: string,
 *   expiresAt?: number
 * }} input - The agent DID and signed challenge fields.
 * @returns {Promise<{authenticated: boolean, reason?: string}>} Whether the
 *   agent authenticated, with a reason on failure.
 */
export async function verifyAuthTool(input) {
  // Resolve agent DID to get their public key
  const resolution = await resolveDID(input.agentDid);
  if(resolution.didResolutionMetadata.error || !resolution.didDocument) {
    return {
      authenticated: false,
      reason: 'Cannot resolve agent DID: ' +
        `${resolution.didResolutionMetadata.error}`
    };
  }

  const publicKey = extractEd25519Key(
    resolution.didDocument.verificationMethod ?? []
  );
  if(!publicKey) {
    return {
      authenticated: false,
      reason: 'No Ed25519 key found in agent DID document'
    };
  }

  /** @type {ChallengeToken} */
  const token = {
    nonce: input.nonce,
    agentDid: input.agentDid,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt ?? input.issuedAt + 300
  };

  const result = await verifyChallengeResponse(
    token,
    input.signatureBase64url,
    publicKey
  );
  return {authenticated: result.valid, reason: result.reason};
}
