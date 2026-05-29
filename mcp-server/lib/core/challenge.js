/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Agent authentication via challenge-response. Pure, no IO.
 */
import { verify, fromBase64url, toBase64url } from "./crypto.js";
import { randomBytes } from "node:crypto";

/**
 * @typedef {object} ChallengeToken
 * @property {string} nonce
 * @property {number} issuedAt
 * @property {number} expiresAt
 * @property {string} agentDid
 */

/**
 * @param {string} agentDid
 * @param {number} [ttlSeconds=300]
 * @returns {ChallengeToken}
 */
export function generateChallenge(agentDid, ttlSeconds = 300) {
  const nonce = toBase64url(randomBytes(32));
  const issuedAt = Math.floor(Date.now() / 1000);
  return { nonce, issuedAt, expiresAt: issuedAt + ttlSeconds, agentDid };
}

/**
 * @param {ChallengeToken} token
 * @returns {Uint8Array}
 */
export function signingInput(token) {
  return new TextEncoder().encode(`${token.nonce}:${token.agentDid}:${token.issuedAt}`);
}

/**
 * @param {ChallengeToken} token
 * @param {number} [nowSeconds]
 * @returns {boolean}
 */
export function isChallengeExpired(token, nowSeconds) {
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  return now >= token.expiresAt;
}

/**
 * @param {ChallengeToken} token
 * @param {string} signatureBase64url
 * @param {Uint8Array} publicKey
 * @param {number} [nowSeconds]
 * @returns {Promise<{valid: boolean, reason?: string}>}
 */
export async function verifyChallengeResponse(token, signatureBase64url, publicKey, nowSeconds) {
  if (isChallengeExpired(token, nowSeconds)) {
    return { valid: false, reason: "Challenge expired" };
  }

  let sigBytes;
  try {
    sigBytes = fromBase64url(signatureBase64url);
  } catch {
    return { valid: false, reason: "Invalid signature encoding" };
  }

  const input = signingInput(token);
  const valid = await verify(input, sigBytes, publicKey);
  if (!valid) {
    return { valid: false, reason: "Signature verification failed" };
  }

  return { valid: true };
}
