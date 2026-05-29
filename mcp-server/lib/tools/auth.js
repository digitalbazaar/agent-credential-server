/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * IO boundary for agent authentication tools.
 */
import { generateChallenge, verifyChallengeResponse } from "../core/challenge.js";
import { resolveDID } from "../core/resolver.js";
import { extractEd25519Key } from "./verify.js";

/**
 * @typedef {import("../core/challenge.js").ChallengeToken} ChallengeToken
 */

/**
 * @param {{agentDid: string, ttlSeconds?: number}} input
 * @returns {Promise<ChallengeToken>}
 */
export async function createChallengeTool(input) {
  return generateChallenge(input.agentDid, input.ttlSeconds);
}

/**
 * @param {{agentDid: string, nonce: string, issuedAt: number, signatureBase64url: string, expiresAt?: number}} input
 * @returns {Promise<{authenticated: boolean, reason?: string}>}
 */
export async function verifyAuthTool(input) {
  // Resolve agent DID to get their public key
  const resolution = await resolveDID(input.agentDid);
  if (resolution.didResolutionMetadata.error || !resolution.didDocument) {
    return {
      authenticated: false,
      reason: `Cannot resolve agent DID: ${resolution.didResolutionMetadata.error}`,
    };
  }

  const publicKey = extractEd25519Key(resolution.didDocument.verificationMethod ?? []);
  if (!publicKey) {
    return { authenticated: false, reason: "No Ed25519 key found in agent DID document" };
  }

  /** @type {ChallengeToken} */
  const token = {
    nonce: input.nonce,
    agentDid: input.agentDid,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt ?? input.issuedAt + 300,
  };

  const result = await verifyChallengeResponse(token, input.signatureBase64url, publicKey);
  return { authenticated: result.valid, reason: result.reason };
}
