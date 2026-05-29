/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure VC logic: issue, parse, verify JWT-format VCs.
 * No IO — testable in isolation.
 */
import { sign, verify, toBase64url, fromBase64url } from "./crypto.js";

/**
 * @typedef {import("./crypto.js").KeyPair} KeyPair
 */

/**
 * Credential claims. Known claims are typed; arbitrary additional claims are
 * permitted via the index signature.
 *
 * @typedef {{
 *   age_verified?: boolean,
 *   over_21?: boolean,
 *   [key: string]: unknown
 * }} VCClaims
 */

/**
 * @typedef {object} VerifiableCredential
 * @property {string} jwt JWT string
 */

/**
 * @typedef {object} CredentialStatus
 * @property {string} id
 * @property {"StatusList2021Entry"} type
 * @property {string} statusPurpose
 * @property {string} statusListIndex
 * @property {string} statusListCredential
 */

/**
 * @typedef {object} VCPayload
 * @property {string} iss issuer DID
 * @property {string} sub subject DID (agent)
 * @property {number} iat issued-at (unix seconds)
 * @property {number} [exp] expiry (unix seconds)
 * @property {string | string[]} [aud] audience restriction
 * @property {{
 *   "@context": string[],
 *   type: string[],
 *   credentialSubject: VCClaims & {id: string},
 *   credentialStatus?: CredentialStatus
 * }} vc
 */

/**
 * @typedef {object} VerifyResult
 * @property {boolean} valid
 * @property {string} [issuer]
 * @property {string} [subject]
 * @property {VCClaims} [claims]
 * @property {string | null} [expires]
 * @property {string} [reason]
 */

/**
 * @param {unknown} obj
 * @returns {string}
 */
function encodeJwtPart(obj) {
  return toBase64url(new TextEncoder().encode(JSON.stringify(obj)));
}

/**
 * @param {string} part
 * @returns {unknown}
 */
function decodeJwtPart(part) {
  return JSON.parse(new TextDecoder().decode(fromBase64url(part)));
}

/**
 * @param {string} subjectDid
 * @param {VCClaims} claims
 * @param {string} issuerDid
 * @param {KeyPair} keyPair
 * @param {number} [expiresInSeconds]
 * @param {{audience?: string | string[], credentialStatus?: CredentialStatus}} [options]
 * @returns {Promise<VerifiableCredential>}
 */
export async function issueCredential(
  subjectDid,
  claims,
  issuerDid,
  keyPair,
  expiresInSeconds,
  options
) {
  const now = Math.floor(Date.now() / 1000);
  /** @type {VCPayload} */
  const payload = {
    iss: issuerDid,
    sub: subjectDid,
    iat: now,
    ...(expiresInSeconds ? { exp: now + expiresInSeconds } : {}),
    ...(options?.audience ? { aud: options.audience } : {}),
    vc: {
      "@context": ["https://www.w3.org/2018/credentials/v1"],
      type: ["VerifiableCredential"],
      credentialSubject: { id: subjectDid, ...claims },
      ...(options?.credentialStatus ? { credentialStatus: options.credentialStatus } : {}),
    },
  };

  const header = encodeJwtPart({ alg: "EdDSA", typ: "JWT" });
  const body = encodeJwtPart(payload);
  const signingInput = `${header}.${body}`;
  const sigBytes = await sign(
    new TextEncoder().encode(signingInput),
    keyPair.privateKey
  );

  const jwt = `${signingInput}.${toBase64url(sigBytes)}`;
  return { jwt };
}

/**
 * @param {string} jwt
 * @returns {VCPayload | null}
 */
export function parseCredential(jwt) {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    return /** @type {VCPayload} */ (decodeJwtPart(parts[1]));
  } catch {
    return null;
  }
}

/**
 * Verify a VC JWT against a raw Ed25519 public key.
 * Caller is responsible for fetching the public key from the DID document.
 *
 * @param {string} jwt
 * @param {Uint8Array} publicKey
 * @param {string} [expectedAudience]
 * @returns {Promise<VerifyResult>}
 */
export async function verifyCredentialJwt(jwt, publicKey, expectedAudience) {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    return { valid: false, reason: "Malformed JWT" };
  }

  const [header, body, sigStr] = parts;
  const signingInput = `${header}.${body}`;

  /** @type {VCPayload} */
  let payload;
  try {
    payload = /** @type {VCPayload} */ (decodeJwtPart(body));
  } catch {
    return { valid: false, reason: "Cannot decode JWT payload" };
  }

  const sigBytes = fromBase64url(sigStr);
  const signingBytes = new TextEncoder().encode(signingInput);
  const valid = await verify(signingBytes, sigBytes, publicKey);

  if (!valid) {
    return { valid: false, reason: "Signature verification failed" };
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp !== undefined && payload.exp < now) {
    return {
      valid: false,
      issuer: payload.iss,
      subject: payload.sub,
      reason: `Credential expired at ${new Date(payload.exp * 1000).toISOString()}`,
    };
  }

  if (expectedAudience !== undefined) {
    const aud = payload.aud;
    if (!aud) {
      return { valid: false, issuer: payload.iss, subject: payload.sub, reason: "VC has no audience but expectedAudience was set" };
    }
    const audArray = Array.isArray(aud) ? aud : [aud];
    if (!audArray.includes(expectedAudience)) {
      return { valid: false, issuer: payload.iss, subject: payload.sub, reason: `Audience mismatch: expected '${expectedAudience}' not in ${JSON.stringify(aud)}` };
    }
  }

  const { id: _id, ...claims } = payload.vc.credentialSubject;

  return {
    valid: true,
    issuer: payload.iss,
    subject: payload.sub,
    claims,
    expires: payload.exp
      ? new Date(payload.exp * 1000).toISOString()
      : null,
  };
}
