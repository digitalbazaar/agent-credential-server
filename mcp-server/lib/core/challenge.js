/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Agent authentication via challenge-response. Pure, no IO.
 *
 * KYA-OS R-L1-1: an agent is identified by a DID. R-L1-5: the agent proves
 * control of its DID by signing a nonce challenge (no key material is
 * transmitted). R-L1-6: an expired or wrongly-signed challenge is rejected
 * (see isChallengeExpired and verifyChallengeResponse).
 */
import {fromBase64url, toBase64url, verify} from './crypto.js';
import {randomBytes} from 'node:crypto';

/**
 * @typedef {object} ChallengeToken
 * @property {string} nonce
 * @property {number} issuedAt
 * @property {number} expiresAt
 * @property {string} agentDid
 */

/**
 * @param {string} agentDid - The agent DID the challenge is issued to.
 * @param {number} [ttlSeconds=300] - Time-to-live in seconds. Default 300.
 * @returns {ChallengeToken} A new challenge token with a random nonce.
 */
export function generateChallenge(agentDid, ttlSeconds = 300) {
  const nonce = toBase64url(randomBytes(32));
  const issuedAt = Math.floor(Date.now() / 1000);
  return {nonce, issuedAt, expiresAt: issuedAt + ttlSeconds, agentDid};
}

/**
 * @param {ChallengeToken} token - The challenge token to derive input from.
 * @returns {Uint8Array} The bytes the agent must sign.
 */
export function signingInput(token) {
  return new TextEncoder().encode(
    `${token.nonce}:${token.agentDid}:${token.issuedAt}`
  );
}

/**
 * @param {ChallengeToken} token - The challenge token to check.
 * @param {number} [nowSeconds] - Current time in unix seconds. Defaults to now.
 * @returns {boolean} True if the challenge has expired.
 */
export function isChallengeExpired(token, nowSeconds) {
  const now = nowSeconds ?? Math.floor(Date.now() / 1000);
  return now >= token.expiresAt;
}

/**
 * @param {ChallengeToken} token - The challenge token that was issued.
 * @param {string} signatureBase64url - The agent's base64url-encoded signature.
 * @param {Uint8Array} publicKey - The agent's Ed25519 public key.
 * @param {number} [nowSeconds] - Current time in unix seconds. Defaults to now.
 * @returns {Promise<{valid: boolean, reason?: string}>} The verify result.
 */
export async function verifyChallengeResponse(
  token,
  signatureBase64url,
  publicKey,
  nowSeconds
) {
  if(isChallengeExpired(token, nowSeconds)) {
    return {valid: false, reason: 'Challenge expired'};
  }

  let sigBytes;
  try {
    sigBytes = fromBase64url(signatureBase64url);
  } catch {
    return {valid: false, reason: 'Invalid signature encoding'};
  }

  const input = signingInput(token);
  const valid = await verify(input, sigBytes, publicKey);
  if(!valid) {
    return {valid: false, reason: 'Signature verification failed'};
  }

  return {valid: true};
}
