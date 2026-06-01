/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {deriveDidKeyIssuer, makeDidKeyDriver, makeDocumentLoader}
  from './didKeyContext.js';
import {fromBase64url} from '../core/crypto.js';
import {issueCredentialDI} from '../core/vc.js';

/**
 * @typedef {import("../core/vc.js").VCClaims} VCClaims
 * @typedef {import("../core/vc.js").DataIntegrityCredential}
 *   DataIntegrityCredential
 * @typedef {import("../core/vc.js").CredentialStatus} CredentialStatus
 */

/**
 * @typedef {object} IssueInput
 * @property {string} subjectDid The subject (agent) DID.
 * @property {VCClaims} claims The claims to embed.
 * @property {string} privateKeyBase64url Base64url Ed25519 seed (32 bytes); the
 *   issuer did:key is derived from it.
 * @property {number} [expiresInSeconds] Optional TTL in seconds.
 * @property {string} [delegatedFrom] Optional delegation chain reference.
 * @property {CredentialStatus} [credentialStatus] Optional credential status.
 */

/**
 * Issue a VC 2.0 Data Integrity credential. The issuer did:key is derived from
 * the signing key, so no separate issuer DID is accepted.
 *
 * @param {IssueInput} input - Subject, claims, signing key, and options.
 * @returns {Promise<DataIntegrityCredential>} The signed credential.
 */
export async function issueCredentialTool(input) {
  // 1. Derive the did:key issuer (DID + signer) from the raw private key
  const privateKey = fromBase64url(input.privateKeyBase64url);
  const driver = makeDidKeyDriver();
  const {did, signer} = await deriveDidKeyIssuer(privateKey, driver);

  // 2. Inject delegatedFrom into claims if present
  const claims = input.delegatedFrom ?
    {...input.claims, delegatedFrom: input.delegatedFrom} :
    input.claims;

  // 3. Issue via the Data Integrity path with a did:key-aware loader
  return issueCredentialDI({
    issuerDid: did,
    subjectDid: input.subjectDid,
    claims,
    signer,
    documentLoader: makeDocumentLoader(driver),
    expiresInSeconds: input.expiresInSeconds,
    credentialStatus: input.credentialStatus
  });
}
