/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  deriveEcdsaDidKeyIssuer, makeEcdsaDidKeyDriver, makeEcdsaDocumentLoader
} from './sdContext.js';
import {issueSdCredential} from '../core/vcSd.js';

/**
 * @typedef {import('../core/vc.js').VCClaims} VCClaims
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
 */

/**
 * Issue a VC 2.0 credential with an ecdsa-sd-2023 base proof. The issuer
 * did:key is derived from the signing key.
 *
 * @param {IssueSdInput} input - Subject, claims, signing key, and options.
 * @returns {Promise<Record<string, unknown>>} The signed base credential.
 */
export async function issueSdCredentialTool(input) {
  const driver = makeEcdsaDidKeyDriver();
  const {did, signer} = await deriveEcdsaDidKeyIssuer({
    publicKeyMultibase: input.publicKeyMultibase,
    secretKeyMultibase: input.privateKeyMultibase
  }, driver);
  return issueSdCredential({
    issuerDid: did,
    subjectDid: input.subjectDid,
    claims: input.claims,
    mandatoryPointers: input.mandatoryPointers ?? DEFAULT_MANDATORY_POINTERS,
    signer,
    documentLoader: makeEcdsaDocumentLoader(driver),
    expiresInSeconds: input.expiresInSeconds,
    validFromInSeconds: input.validFromInSeconds ?? -1
  });
}
