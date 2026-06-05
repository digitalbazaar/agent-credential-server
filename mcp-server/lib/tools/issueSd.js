/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  deriveSdDidKeyIssuer, makeSdDidKeyDriver, makeSdDocumentLoader
} from './sdContext.js';
import {issueSdCredential} from '../core/vcSd.js';

/**
 * @typedef {import('../core/vc.js').VCClaims} VCClaims
 * @typedef {import('../core/vcSd.js').SdCryptosuite} SdCryptosuite
 */

/**
 * Default mandatory pointers: only what a verifier needs to trust and bound the
 * credential. Substantive personal data stays selective.
 *
 * KYA-OS R-L3-3: issuer + validity are mandatory in every reveal document;
 * DOB, name, and the age flags are never mandatory.
 */
const DEFAULT_MANDATORY_POINTERS = ['/issuer', '/validFrom', '/validUntil'];

/**
 * @typedef {object} IssueSdInput
 * @property {string} subjectDid The subject (agent) DID.
 * @property {VCClaims} claims The full claim set, including precomputed
 *   age_over_NN flags.
 * @property {string} publicKeyMultibase The issuer's P-256 public-key
 *   multibase.
 * @property {string} privateKeyMultibase The issuer's P-256 secret-key
 *   multibase; together with the public key the issuer did:key is derived.
 * @property {string[]} [mandatoryPointers] JSON pointers always revealed;
 *   defaults to issuer + validity.
 * @property {number} [expiresInSeconds] Optional TTL in seconds.
 * @property {number} [validFromInSeconds] Optional seconds from now until
 *   valid; defaults to -1 (valid as of issuance).
 * @property {SdCryptosuite} [cryptosuite] Optional SD cryptosuite; defaults to
 *   ecdsa-sd-2023. Use 'bbs-2023' for unlinkable disclosure (a BLS key).
 */

/**
 * Issue a VC 2.0 selective-disclosure base credential. The issuer did:key is
 * derived from the signing key (P-256 for ecdsa-sd-2023, BLS for bbs-2023).
 *
 * @param {IssueSdInput} input - Subject, claims, signing key, and options.
 * @returns {Promise<Record<string, unknown>>} The signed base credential.
 */
export async function issueSdCredentialTool(input) {
  const {cryptosuite} = input;
  const driver = makeSdDidKeyDriver(cryptosuite);
  const {did, signer} = await deriveSdDidKeyIssuer({
    publicKeyMultibase: input.publicKeyMultibase,
    secretKeyMultibase: input.privateKeyMultibase
  }, driver, cryptosuite);
  return issueSdCredential({
    issuerDid: did,
    subjectDid: input.subjectDid,
    claims: input.claims,
    mandatoryPointers: input.mandatoryPointers ?? DEFAULT_MANDATORY_POINTERS,
    signer,
    documentLoader: makeSdDocumentLoader(driver),
    expiresInSeconds: input.expiresInSeconds,
    validFromInSeconds: input.validFromInSeconds ?? -1,
    cryptosuite
  });
}
