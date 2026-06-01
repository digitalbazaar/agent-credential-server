/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure VC logic. Two paths coexist during the Phase 1 migration:
 *   - Data Integrity (primary): issue/verify VC 2.0 with eddsa-rdfc-2022
 *     proofs via @digitalbazaar/vc.
 *   - Legacy JWT (the L1 nod): hand-rolled JWT issue/parse/verify, retained
 *     for the delegation chain until its linkage is re-based.
 * No IO of its own — keys, signers, and the document loader are passed in.
 */
import * as vcjs from '@digitalbazaar/vc';
import {fromBase64url, sign, toBase64url, verify} from './crypto.js';
import {AGENT_CREDENTIAL_CONTEXT_URL} from './documentLoader.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as eddsaRdfc2022}
  from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';

/**
 * @typedef {import("./crypto.js").KeyPair} KeyPair
 * @typedef {import("./documentLoader.js").DocumentLoader} DocumentLoader
 */

const VC2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';

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
 * @property {string} jwt JWT string.
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
 * @property {string} iss Issuer DID.
 * @property {string} sub Subject DID (agent).
 * @property {number} iat Issued-at (unix seconds).
 * @property {number} [exp] Expiry (unix seconds).
 * @property {string | string[]} [aud] Audience restriction.
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
 * @param {unknown} obj - The value to encode as a JWT part.
 * @returns {string} The base64url-encoded JSON.
 */
function encodeJwtPart(obj) {
  return toBase64url(new TextEncoder().encode(JSON.stringify(obj)));
}

/**
 * @param {string} part - The base64url-encoded JWT part.
 * @returns {unknown} The decoded JSON value.
 */
function decodeJwtPart(part) {
  return JSON.parse(new TextDecoder().decode(fromBase64url(part)));
}

/**
 * @param {string} subjectDid - The subject (agent) DID.
 * @param {VCClaims} claims - The claims to embed in the credential subject.
 * @param {string} issuerDid - The issuer DID.
 * @param {KeyPair} keyPair - The issuer's Ed25519 key pair.
 * @param {number} [expiresInSeconds] - Lifetime in seconds; omit for no expiry.
 * @param {{
 *   audience?: string | string[],
 *   credentialStatus?: CredentialStatus
 * }} [options] - Optional audience restriction and credential status.
 * @returns {Promise<VerifiableCredential>} The signed JWT-format credential.
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
    ...(expiresInSeconds ? {exp: now + expiresInSeconds} : {}),
    ...(options?.audience ? {aud: options.audience} : {}),
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1'],
      type: ['VerifiableCredential'],
      credentialSubject: {id: subjectDid, ...claims},
      ...(options?.credentialStatus ?
        {credentialStatus: options.credentialStatus} :
        {})
    }
  };

  const header = encodeJwtPart({alg: 'EdDSA', typ: 'JWT'});
  const body = encodeJwtPart(payload);
  const signingInput = `${header}.${body}`;
  const sigBytes = await sign(
    new TextEncoder().encode(signingInput),
    keyPair.privateKey
  );

  const jwt = `${signingInput}.${toBase64url(sigBytes)}`;
  return {jwt};
}

/**
 * @param {string} jwt - The JWT-format credential.
 * @returns {VCPayload | null} The decoded payload, or null if malformed.
 */
export function parseCredential(jwt) {
  const parts = jwt.split('.');
  if(parts.length !== 3) {
    return null;
  }
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
 * @param {string} jwt - The JWT-format credential to verify.
 * @param {Uint8Array} publicKey - The issuer's Ed25519 public key.
 * @param {string} [expectedAudience] - If set, the VC must include this aud.
 * @returns {Promise<VerifyResult>} The verification result.
 */
export async function verifyCredentialJwt(jwt, publicKey, expectedAudience) {
  const parts = jwt.split('.');
  if(parts.length !== 3) {
    return {valid: false, reason: 'Malformed JWT'};
  }

  const [header, body, sigStr] = parts;
  const signingInput = `${header}.${body}`;

  /** @type {VCPayload} */
  let payload;
  try {
    payload = /** @type {VCPayload} */ (decodeJwtPart(body));
  } catch {
    return {valid: false, reason: 'Cannot decode JWT payload'};
  }

  const sigBytes = fromBase64url(sigStr);
  const signingBytes = new TextEncoder().encode(signingInput);
  const valid = await verify(signingBytes, sigBytes, publicKey);

  if(!valid) {
    return {valid: false, reason: 'Signature verification failed'};
  }

  const now = Math.floor(Date.now() / 1000);
  if(payload.exp !== undefined && payload.exp < now) {
    return {
      valid: false,
      issuer: payload.iss,
      subject: payload.sub,
      reason: 'Credential expired at ' +
        `${new Date(payload.exp * 1000).toISOString()}`
    };
  }

  if(expectedAudience !== undefined) {
    const aud = payload.aud;
    if(!aud) {
      return {
        valid: false,
        issuer: payload.iss,
        subject: payload.sub,
        reason: 'VC has no audience but expectedAudience was set'
      };
    }
    const audArray = Array.isArray(aud) ? aud : [aud];
    if(!audArray.includes(expectedAudience)) {
      return {
        valid: false,
        issuer: payload.iss,
        subject: payload.sub,
        reason: `Audience mismatch: expected '${expectedAudience}' ` +
          `not in ${JSON.stringify(aud)}`
      };
    }
  }

  // claims are every credentialSubject field except the subject's id
  /** @type {VCClaims & {id?: string}} */
  const claims = {...payload.vc.credentialSubject};
  delete claims.id;

  return {
    valid: true,
    issuer: payload.iss,
    subject: payload.sub,
    claims,
    expires: payload.exp ?
      new Date(payload.exp * 1000).toISOString() :
      null
  };
}

// --- Data Integrity (VC 2.0) path ---

/**
 * A signed VC 2.0 Data Integrity credential. Uses object-literal typedef
 * syntax so the `@context` key can be quoted (an `@property` tag cannot name a
 * property beginning with `@`).
 *
 * @typedef {{
 *   '@context': (string | object)[],
 *   type: string[],
 *   issuer: string,
 *   validUntil?: string,
 *   credentialSubject: VCClaims & {id: string},
 *   credentialStatus?: CredentialStatus,
 *   proof: {type: string, cryptosuite: string}
 * }} DataIntegrityCredential
 */

/**
 * @typedef {object} IssueDIInput
 * @property {string} issuerDid - The issuer DID (must resolve to the signer's
 *   key via the document loader; for did:key it is derived from the key).
 * @property {string} subjectDid - The subject (agent) DID.
 * @property {VCClaims} claims - The claims to embed in the credential subject.
 * @property {object} signer - An ed25519-multikey signer for the issuer key.
 * @property {DocumentLoader} documentLoader - Loader resolving the issuer DID
 *   and the credential contexts.
 * @property {number} [expiresInSeconds] - Lifetime in seconds; omit for no
 *   expiry. Negative values produce an already-expired credential (for tests).
 * @property {CredentialStatus} [credentialStatus] - Optional status entry.
 */

/**
 * @typedef {object} VerifyDIInput
 * @property {DataIntegrityCredential} credential - The credential to verify.
 * @property {DocumentLoader} documentLoader - Loader resolving the issuer DID
 *   and the credential contexts.
 */

/**
 * @typedef {object} VerifyDIResult
 * @property {boolean} valid
 * @property {string} [issuer]
 * @property {string} [subject]
 * @property {VCClaims} [claims]
 * @property {string | null} [expires]
 * @property {string} [reason]
 */

/**
 * Issue a VC 2.0 credential with an eddsa-rdfc-2022 Data Integrity proof.
 *
 * @param {IssueDIInput} input - Issuer, subject, claims, signer, and loader.
 * @returns {Promise<DataIntegrityCredential>} The signed credential.
 */
export async function issueCredentialDI(input) {
  const {
    issuerDid, subjectDid, claims, signer, documentLoader,
    expiresInSeconds, credentialStatus
  } = input;

  const credential = {
    '@context': [VC2_CONTEXT_URL, AGENT_CREDENTIAL_CONTEXT_URL],
    type: ['VerifiableCredential'],
    issuer: issuerDid,
    ...(expiresInSeconds === undefined ? {} : {
      validUntil: new Date(Date.now() + expiresInSeconds * 1000).toISOString()
    }),
    credentialSubject: {id: subjectDid, ...claims},
    ...(credentialStatus ? {credentialStatus} : {})
  };

  const suite = new DataIntegrityProof({signer, cryptosuite: eddsaRdfc2022});
  return /** @type {Promise<DataIntegrityCredential>} */ (
    vcjs.issue({credential, suite, documentLoader})
  );
}

/**
 * Verify a VC 2.0 Data Integrity credential. Returns a domain result object;
 * crypto/encoding failures are caught and converted, never thrown to caller.
 *
 * @param {VerifyDIInput} input - The credential and document loader.
 * @returns {Promise<VerifyDIResult>} The verification result.
 */
export async function verifyCredentialDI(input) {
  const {credential, documentLoader} = input;
  const suite = new DataIntegrityProof({cryptosuite: eddsaRdfc2022});

  // 1. Verify proof, expiry (validUntil), and structure via the vc library
  let result;
  try {
    result = await vcjs.verifyCredential({credential, suite, documentLoader});
  } catch(e) {
    return {valid: false, reason: `Verification threw: ${asMessage(e)}`};
  }

  // 2. Convert the library's {verified, error} into a domain result object
  if(!result.verified) {
    return {valid: false, reason: verifyErrorReason(result)};
  }

  // 3. Extract issuer, subject, and claims from the verified credential
  /** @type {VCClaims & {id?: string}} */
  const claims = {...credential.credentialSubject};
  delete claims.id;

  return {
    valid: true,
    issuer: typeof credential.issuer === 'string' ?
      credential.issuer :
      undefined,
    subject: credential.credentialSubject.id,
    claims,
    expires: credential.validUntil ?? null
  };
}

/**
 * Extract a human-readable reason from a failed verifyCredential result.
 *
 * @param {{error?: Error & {errors?: Error[]}}} result - The verify result.
 * @returns {string} A non-sensitive failure reason.
 */
function verifyErrorReason(result) {
  const error = result.error;
  if(!error) {
    return 'Verification failed';
  }
  // surface the most specific message available without leaking key material
  const specific = error.errors?.[0]?.message;
  return specific ?? asMessage(error);
}

/**
 * Coerce an unknown thrown value to a message string.
 *
 * @param {unknown} e - The thrown value.
 * @returns {string} The message.
 */
function asMessage(e) {
  return e instanceof Error ? e.message : String(e);
}
