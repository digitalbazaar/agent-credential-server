/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure selective-disclosure logic: issue a base proof, derive a reveal
 * document, and verify it, using the three-cryptosuite split (sign / disclose
 * / verify) via @digitalbazaar/vc. No IO of its own — the signer and document
 * loader are passed in. Purely additive to the eddsa-rdfc-2022 path.
 *
 * Two cryptosuites share this flow, selected by the `cryptosuite` option:
 *   - 'ecdsa-sd-2023' (default, Phase 2): P-256 keys; presentations are
 *     LINKABLE.
 *   - 'bbs-2023' (Phase 2.5): BLS12-381 keys; presentations are UNLINKABLE
 *     (two derivations from one credential cannot be correlated).
 * The flow is identical; only the factory trio and the key type differ.
 *
 * KYA-OS R-L3-1: a holder derives a presentation revealing a subset of claims.
 * R-L3-2 / R-L3-9: a derived presentation (ecdsa-sd-2023 / bbs-2023) verifies
 * only if the revealed claims were in the issuer's original signature.
 * R-L3-7: bbs-2023 presentations are unlinkable.
 */
import * as bbs2023 from '@digitalbazaar/bbs-2023-cryptosuite';
import * as ecdsaSd2023 from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import * as vcjs from '@digitalbazaar/vc';
import {AGENT_CREDENTIAL_CONTEXT_URL} from './documentLoader.js';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';

/**
 * @typedef {import("./documentLoader.js").DocumentLoader} DocumentLoader
 * @typedef {import("./vc.js").VCClaims} VCClaims
 * @typedef {'ecdsa-sd-2023' | 'bbs-2023'} SdCryptosuite
 */

const VC2_CONTEXT_URL = 'https://www.w3.org/ns/credentials/v2';

const DEFAULT_CRYPTOSUITE = 'ecdsa-sd-2023';

/**
 * @typedef {object} SdCryptosuiteFactories
 * @property {(options: {mandatoryPointers: string[]}) => unknown}
 *   createSignCryptosuite
 * @property {(options: {selectivePointers: string[]}) => unknown}
 *   createDiscloseCryptosuite
 * @property {() => unknown} createVerifyCryptosuite
 */

// The sign/disclose/verify factory trio for each supported SD cryptosuite.
// The discriminator stays in this one pure place; the tool layer only passes
// a string.
/** @type {Record<string, SdCryptosuiteFactories>} */
const CRYPTOSUITES = {
  'ecdsa-sd-2023': ecdsaSd2023,
  'bbs-2023': bbs2023
};

/**
 * Resolve the cryptosuite factory trio for a kind, defaulting to ecdsa-sd-2023
 * (the conservative, mature suite).
 *
 * @param {SdCryptosuite} [kind] - The cryptosuite kind.
 * @returns {SdCryptosuiteFactories} The sign/disclose/verify factories.
 */
function resolveCryptosuite(kind = DEFAULT_CRYPTOSUITE) {
  const suite = CRYPTOSUITES[kind];
  if(!suite) {
    throw new Error(
      `Unknown cryptosuite "${kind}". Supported: ` +
      `${Object.keys(CRYPTOSUITES).join(', ')}.`);
  }
  return suite;
}

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
 * @property {SdCryptosuite} [cryptosuite] - The SD cryptosuite; defaults to
 *   ecdsa-sd-2023.
 */

/**
 * Issue a VC 2.0 credential with a selective-disclosure base proof.
 *
 * @param {IssueSdInput} input - Issuer, subject, claims, mandatory pointers,
 *   signer, loader, and optional cryptosuite.
 * @returns {Promise<Record<string, unknown>>} The signed base credential.
 */
export async function issueSdCredential(input) {
  const {
    issuerDid, subjectDid, claims, mandatoryPointers, signer, documentLoader,
    expiresInSeconds, validFromInSeconds, cryptosuite
  } = input;
  const {createSignCryptosuite} = resolveCryptosuite(cryptosuite);

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
 * @property {SdCryptosuite} [cryptosuite] - The SD cryptosuite; defaults to
 *   ecdsa-sd-2023. Must match the suite the base proof was signed with.
 */

/**
 * Derive a reveal document disclosing only the selected claims (plus the
 * issuer's mandatory claims). The undisclosed claims are absent from the
 * output, not merely hidden.
 *
 * @param {DeriveInput} input - Base credential, selective pointers, loader,
 *   and optional cryptosuite.
 * @returns {Promise<Record<string, unknown>>} The reveal document.
 */
export async function deriveDisclosure(input) {
  const {credential, selectivePointers, documentLoader, cryptosuite} = input;
  const {createDiscloseCryptosuite} = resolveCryptosuite(cryptosuite);
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
 * @property {SdCryptosuite} [cryptosuite] - The SD cryptosuite; defaults to
 *   ecdsa-sd-2023. Must match the suite the reveal document was derived with.
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
  const {revealDocument, documentLoader, cryptosuite} = input;
  const {createVerifyCryptosuite} = resolveCryptosuite(cryptosuite);
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
