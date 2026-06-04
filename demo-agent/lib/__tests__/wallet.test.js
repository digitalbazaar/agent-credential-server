/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The wallet seam (holder Model B): the wallet holds the full SD credential and
 * exposes only requestDisclosure(claims) -> reveal document. The agent calls it
 * but cannot read the full credential, so the birthdate never crosses into
 * agent-side code (R-L3-5). These tests prove the seam derives minimal reveal
 * documents and never exposes the hidden claims.
 */
import * as EcdsaMultikey from 'mcp-server/lib/core/ecdsa.js';
import {createWallet} from '../wallet.js';
import {issueSdCredentialTool} from 'mcp-server/lib/tools/issueSd.js';

const AGENT_DID = 'did:example:agent';

/**
 * Issue a base SD credential carrying age flags + hidden PII.
 *
 * @returns {Promise<Record<string, unknown>>} The signed base credential.
 */
async function issueBase() {
  const key = await EcdsaMultikey.generateEcdsaMultikey();
  const exported = /** @type {{
   *   publicKeyMultibase: string, secretKeyMultibase: string
   * }} */ (await key.export({publicKey: true, secretKey: true}));
  return issueSdCredentialTool({
    subjectDid: AGENT_DID,
    claims: {
      birthdate: '2000-01-01',
      age_over_18: true,
      age_over_21: true,
      age_over_65: false,
      name: 'Pat Holder'
    },
    publicKeyMultibase: exported.publicKeyMultibase,
    privateKeyMultibase: exported.secretKeyMultibase,
    expiresInSeconds: 3600
  });
}

describe('createWallet', () => {
  it('exposes requestDisclosure but not the full credential', async () => {
    const wallet = createWallet(await issueBase());
    expect(typeof wallet.requestDisclosure).toBe('function');
    // the seam must not surface the full credential as a readable property
    expect(/** @type {any} */ (wallet).credential).toBeUndefined();
  });

  it('derives a reveal document disclosing only the requested claim',
    async () => {
      const wallet = createWallet(await issueBase());
      const reveal = await wallet.requestDisclosure(['age_over_21']);
      const subject = /** @type {Record<string, unknown>} */ (
        reveal.credentialSubject
      );
      expect(subject.age_over_21).toBe(true);
      // hidden claims must never appear in the reveal document (R-L3-5)
      expect(subject.birthdate).toBeUndefined();
      expect(subject.name).toBeUndefined();
      expect(subject.age_over_18).toBeUndefined();
      expect(subject.age_over_65).toBeUndefined();
    });

  it('never includes the birthdate anywhere in the reveal document',
    async () => {
      const wallet = createWallet(await issueBase());
      const reveal = await wallet.requestDisclosure(['age_over_21']);
      // the DOB must not leak via any nested field or serialization
      expect(JSON.stringify(reveal)).not.toContain('2000-01-01');
    });
});
