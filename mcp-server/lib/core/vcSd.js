/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure selective-disclosure logic: issue a base proof, derive a reveal
 * document, and verify it, using the ecdsa-sd-2023 three-cryptosuite split via
 * @digitalbazaar/vc. No IO of its own — the signer and document loader are
 * passed in. The ECDSA analog of vc.js; purely additive (Phase 2).
 *
 * KYA-OS R-L3-1: a holder derives a presentation revealing a subset of claims.
 * R-L3-2: a derived presentation verifies only if the revealed claims were in
 * the issuer's original signature.
 */
import * as vcjs from '@digitalbazaar/vc';
import {
  createDiscloseCryptosuite, createSignCryptosuite, createVerifyCryptosuite
} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {AGENT_CREDENTIAL_CONTEXT_URL} from './documentLoader.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';

/**
 * @typedef {import("./documentLoader.js").DocumentLoader} DocumentLoader
 * @typedef {import("./vc.js").VCClaims} VCClaims
 */

const VC2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';

/**
 * @typedef {object} IssueSdInput
 * @property {string} issuerDid - The issuer DID (resolves to the signer key).
 * @property {string} subjectDid - The subject (agent) DID.
 * @property {VCClaims} claims - The full claim set, including the precomputed
 *   age_over_NN flags.
 * @property {string[]} mandatoryPointers - JSON pointers always revealed (e.g.
 *   '/issuer', '/validFrom', '/validUntil').
 * @property {object} signer - A P-256 ecdsa-multikey signer for the issuer.
 * @property {DocumentLoader} documentLoader - Loader resolving the issuer DID
 *   and contexts.
 * @property {number} [expiresInSeconds] - Lifetime in seconds; omit for none.
 * @property {number} [validFromInSeconds] - Seconds from now until valid.
 */

/**
 * Issue a VC 2.0 credential with an ecdsa-sd-2023 base (SD) proof.
 *
 * @param {IssueSdInput} input - Issuer, subject, claims, mandatory pointers,
 *   signer, and loader.
 * @returns {Promise<Record<string, unknown>>} The signed base credential.
 */
export async function issueSdCredential(input) {
  const {
    issuerDid, subjectDid, claims, mandatoryPointers, signer, documentLoader,
    expiresInSeconds, validFromInSeconds
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
    credentialSubject: {id: subjectDid, ...claims}
  };

  const suite = new DataIntegrityProof({
    signer, cryptosuite: createSignCryptosuite({mandatoryPointers})
  });
  return vcjs.issue({credential, suite, documentLoader});
}

/**
 * @typedef {object} DeriveInput
 * @property {Record<string, unknown>} credential - The base SD credential.
 * @property {string[]} selectivePointers - JSON pointers to the claims to
 *   disclose (e.g. '/credentialSubject/age_over_21').
 * @property {DocumentLoader} documentLoader - The document loader.
 */

/**
 * Derive a reveal document disclosing only the selected claims (plus the
 * issuer's mandatory claims). The undisclosed claims are absent from the
 * output, not merely hidden.
 *
 * @param {DeriveInput} input - Base credential, selective pointers, loader.
 * @returns {Promise<Record<string, unknown>>} The reveal document.
 */
export async function deriveDisclosure(input) {
  const {credential, selectivePointers, documentLoader} = input;
  const suite = new DataIntegrityProof({
    cryptosuite: createDiscloseCryptosuite({selectivePointers})
  });
  return vcjs.derive({
    verifiableCredential: credential, suite, documentLoader
  });
}

/**
 * @typedef {object} VerifyDisclosureInput
 * @property {Record<string, unknown>} revealDocument - The reveal document.
 * @property {DocumentLoader} documentLoader - The document loader.
 */

/**
 * @typedef {object} VerifyDisclosureResult
 * @property {boolean} valid
 * @property {string} [issuer]
 * @property {VCClaims} [revealedClaims]
 * @property {string} [reason]
 */

/**
 * Verify a reveal document's derived proof. Returns a domain result object;
 * crypto/encoding failures are caught and converted, never thrown.
 *
 * @param {VerifyDisclosureInput} input - The reveal document and loader.
 * @returns {Promise<VerifyDisclosureResult>} The verification result.
 */
export async function verifyDisclosure(input) {
  const {revealDocument, documentLoader} = input;
  const suite = new DataIntegrityProof({
    cryptosuite: createVerifyCryptosuite()
  });

  let result;
  try {
    result = await vcjs.verifyCredential({
      credential: revealDocument, suite, documentLoader
    });
  } catch(e) {
    const message = e instanceof Error ? e.message : String(e);
    return {valid: false, reason: `Verification threw: ${message}`};
  }

  if(!result.verified) {
    const err = result.error;
    const reason = err?.errors?.[0]?.message ?? err?.message ??
      'Reveal document not verified';
    return {valid: false, reason};
  }

  const subject = /** @type {Record<string, unknown>} */ (
    revealDocument.credentialSubject ?? {}
  );
  /** @type {VCClaims} */
  const revealedClaims = {...subject};
  delete revealedClaims.id;

  return {
    valid: true,
    issuer: typeof revealDocument.issuer === 'string' ?
      revealDocument.issuer :
      undefined,
    revealedClaims
  };
}
