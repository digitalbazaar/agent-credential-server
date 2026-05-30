/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {fromBase64url} from '../core/crypto.js';
import {issueCredential} from '../core/vc.js';

/**
 * @typedef {import("../core/vc.js").VCClaims} VCClaims
 * @typedef {import("../core/vc.js").VerifiableCredential} VerifiableCredential
 * @typedef {import("../core/vc.js").CredentialStatus} CredentialStatus
 * @typedef {import("../core/crypto.js").KeyPair} KeyPair
 */

/**
 * @typedef {object} IssueInput
 * @property {string} subjectDid
 * @property {VCClaims} claims
 * @property {string} issuerDid
 * @property {string} privateKeyBase64url Base64url-encoded Ed25519 private
 *   key (32 bytes).
 * @property {number} [expiresInSeconds] Optional TTL in seconds.
 * @property {string | string[]} [audience] Optional audience restriction.
 * @property {string} [delegatedFrom] Optional delegation chain reference.
 * @property {CredentialStatus} [credentialStatus] Optional credential status
 *   for revocation support.
 */

/**
 * Issue a signed JWT Verifiable Credential from the given input.
 *
 * @param {IssueInput} input - Subject, claims, issuer, key, and options.
 * @returns {Promise<VerifiableCredential>} The signed Verifiable Credential.
 */
export async function issueCredentialTool(input) {
  const privateKey = fromBase64url(input.privateKeyBase64url);
  const {getPublicKeyAsync} = await import('@noble/ed25519');
  const publicKey = await getPublicKeyAsync(privateKey);
  /** @type {KeyPair} */
  const keyPair = {privateKey, publicKey};

  // Inject delegatedFrom into claims if present
  const claims = input.delegatedFrom ?
    {...input.claims, delegatedFrom: input.delegatedFrom} :
    input.claims;

  return issueCredential(
    input.subjectDid,
    claims,
    input.issuerDid,
    keyPair,
    input.expiresInSeconds,
    {
      audience: input.audience,
      credentialStatus: input.credentialStatus
    }
  );
}
