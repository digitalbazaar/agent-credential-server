/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Delegation chain verification. Pure (keys passed in, no IO).
 */
import {parseCredential, verifyCredentialJwt} from './vc.js';
import {sha256} from '@noble/hashes/sha2.js';
import {toBase64url} from './crypto.js';

/**
 * @typedef {import("./vc.js").VCPayload} VCPayload
 */

/**
 * @typedef {object} ChainLink
 * @property {string} vcJwt
 * @property {Uint8Array} issuerPublicKey
 */

/**
 * @typedef {object} ChainEntry
 * @property {string} issuer
 * @property {string} subject
 */

/**
 * @param {VCPayload} payload - The credential payload to inspect.
 * @returns {string | null} The delegatedFrom hash, or null if absent.
 */
export function extractDelegatedFrom(payload) {
  const val = payload.vc.credentialSubject.delegatedFrom;
  return typeof val === 'string' ? val : null;
}

/**
 * @param {string} input - The string to hash.
 * @returns {string} The base64url-encoded SHA-256 digest.
 */
function sha256base64url(input) {
  return toBase64url(sha256(new TextEncoder().encode(input)));
}

/**
 * @param {ChainLink[]} links - The delegation chain links, root-first.
 * @param {string} leafAgentDid - The expected subject of the final link.
 * @param {number} [maxDepth=5] - Maximum allowed chain length. Default 5.
 * @returns {Promise<{
 *   valid: boolean,
 *   depth: number,
 *   chain?: ChainEntry[],
 *   reason?: string
 * }>} The chain verification result.
 */
export async function verifyDelegationChain(links, leafAgentDid, maxDepth = 5) {
  if(links.length === 0) {
    return {valid: false, depth: 0, reason: 'Empty chain'};
  }

  if(links.length > maxDepth) {
    return {
      valid: false,
      depth: links.length,
      reason: `Chain depth ${links.length} exceeds max depth ${maxDepth}`
    };
  }

  /** @type {ChainEntry[]} */
  const chain = [];
  const seenIssuers = new Set();
  /** @type {string | null} */
  let prevSubject = null;

  for(let i = 0; i < links.length; i++) {
    const {vcJwt, issuerPublicKey} = links[i];

    // Verify the signature and expiry
    const verifyResult = await verifyCredentialJwt(vcJwt, issuerPublicKey);
    if(!verifyResult.valid) {
      return {
        valid: false,
        depth: i + 1,
        reason: `Link ${i}: ${verifyResult.reason}`
      };
    }

    const payload = /** @type {VCPayload} */ (parseCredential(vcJwt));
    const issuer = payload.iss;
    const subject = payload.sub;

    // Circular reference detection
    if(seenIssuers.has(issuer)) {
      return {
        valid: false,
        depth: i + 1,
        reason: `Issuer ${issuer} already seen — circular reference detected`
      };
    }
    seenIssuers.add(issuer);

    // Chain continuity: each issuer must equal previous subject
    if(prevSubject !== null && issuer !== prevSubject) {
      return {
        valid: false,
        depth: i + 1,
        reason: `Link ${i}: issuer (${issuer}) does not match ` +
          `previous subject (${prevSubject})`
      };
    }

    // Verify delegatedFrom hash (for links beyond the first)
    if(i > 0) {
      const parentJwt = links[i - 1].vcJwt;
      const expectedHash = sha256base64url(parentJwt);
      const actualHash = extractDelegatedFrom(payload);
      // Only enforce if delegatedFrom is present — it's optional for
      // root delegation
      if(actualHash !== null && actualHash !== expectedHash) {
        return {
          valid: false,
          depth: i + 1,
          reason: `Link ${i}: delegatedFrom hash mismatch`
        };
      }
    }

    chain.push({issuer, subject});
    prevSubject = subject;
  }

  // Leaf subject must equal leafAgentDid
  const leafSubject = chain[chain.length - 1].subject;
  if(leafSubject !== leafAgentDid) {
    return {
      valid: false,
      depth: links.length,
      reason: `Leaf subject (${leafSubject}) does not match ` +
        `expected leaf agent DID (${leafAgentDid})`
    };
  }

  return {valid: true, depth: links.length, chain};
}
