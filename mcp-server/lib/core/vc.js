/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure VC logic: issue and verify VC 2.0 credentials with eddsa-rdfc-2022
 * Data Integrity proofs via @digitalbazaar/vc. No IO of its own — the signer
 * and document loader are passed in.
 */
import * as vcjs from '@digitalbazaar/vc';
import {AGENT_CREDENTIAL_CONTEXT_URL} from './documentLoader.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as eddsaRdfc2022}
  from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';

/**
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
 * @typedef {object} CredentialStatus
 * @property {string} id
 * @property {"StatusList2021Entry"} type
 * @property {string} statusPurpose
 * @property {string} statusListIndex
 * @property {string} statusListCredential
 */

/**
 * A signed VC 2.0 Data Integrity credential. Uses object-literal typedef
 * syntax so the `@context` key can be quoted (an `@property` tag cannot name a
 * property beginning with `@`).
 *
 * @typedef {{
 *   '@context': (string | object)[],
 *   type: string[],
 *   issuer: string,
 *   validFrom?: string,
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
 * @property {number} [validFromInSeconds] - Seconds from now until the
 *   credential becomes valid; omit for immediately valid. Positive values
 *   produce a not-yet-valid credential (for tests).
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
    expiresInSeconds, validFromInSeconds, credentialStatus
  } = input;

  const credential = {
    '@context': [VC2_CONTEXT_URL, AGENT_CREDENTIAL_CONTEXT_URL],
    type: ['VerifiableCredential'],
    issuer: issuerDid,
    ...(validFromInSeconds === undefined ? {} : {
      validFrom: new Date(Date.now() + validFromInSeconds * 1000).toISOString()
    }),
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
