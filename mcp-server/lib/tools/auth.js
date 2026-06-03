/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * IO boundary for agent authentication tools.
 */
import {generateChallenge, verifyChallengeResponse} from '../core/challenge.js';
import {resolveAgentKey} from './didKeyContext.js';

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
  // Resolve agent DID to get their public key (did:key offline, else network)
  const publicKey = await resolveAgentKey(input.agentDid);
  if(!publicKey) {
    return {
      authenticated: false,
      reason: `Cannot resolve agent DID: ${input.agentDid}`
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
