/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {generateKeyPair} from '../core/crypto.js';
import {issueCredential} from '../core/vc.js';

const ISSUER_DID = 'did:key:z6MkHuman';
const AGENT_DID = 'did:key:z6MkAgent';

/**
 * Decode a JWT body to its payload object.
 *
 * @param {string} jwt - The JWT string.
 * @returns {any} The decoded payload.
 */
function decodePayload(jwt) {
  const body = jwt.split('.')[1];
  return JSON.parse(Buffer.from(body, 'base64url').toString());
}

describe('issueCredential (legacy JWT path)', () => {
  it('issues a well-formed three-part JWT', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {age_verified: true, over_21: true}, ISSUER_DID, kp
    );
    expect(vc.jwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
  });

  it('embeds the issuer, subject, and claims in the payload', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {age_verified: true, over_21: true}, ISSUER_DID, kp
    );
    const payload = decodePayload(vc.jwt);
    expect(payload.iss).toBe(ISSUER_DID);
    expect(payload.sub).toBe(AGENT_DID);
    expect(payload.vc.credentialSubject).toMatchObject({
      id: AGENT_DID, age_verified: true, over_21: true
    });
  });

  it('sets an expiry when a TTL is given', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {over_21: true}, ISSUER_DID, kp, 3600
    );
    const payload = decodePayload(vc.jwt);
    expect(payload.exp).toBe(payload.iat + 3600);
  });

  it('omits expiry when no TTL is given', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(AGENT_DID, {}, ISSUER_DID, kp);
    const payload = decodePayload(vc.jwt);
    expect(payload.exp).toBeUndefined();
  });

  it('embeds a single audience when given', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {role: 'admin'}, ISSUER_DID, kp, undefined,
      {audience: 'did:web:resource.example.com'}
    );
    const payload = decodePayload(vc.jwt);
    expect(payload.aud).toBe('did:web:resource.example.com');
  });

  it('embeds an array audience when given', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {}, ISSUER_DID, kp, undefined,
      {audience: ['did:web:a.example.com', 'did:web:b.example.com']}
    );
    const payload = decodePayload(vc.jwt);
    expect(payload.aud).toEqual([
      'did:web:a.example.com', 'did:web:b.example.com'
    ]);
  });

  it('embeds a credentialStatus when given', async () => {
    const kp = await generateKeyPair();
    /** @type {import('../core/vc.js').CredentialStatus} */
    const status = {
      id: 'https://status.example/1#4',
      type: 'StatusList2021Entry',
      statusPurpose: 'revocation',
      statusListIndex: '4',
      statusListCredential: 'https://status.example/1'
    };
    const vc = await issueCredential(
      AGENT_DID, {}, ISSUER_DID, kp, undefined, {credentialStatus: status}
    );
    const payload = decodePayload(vc.jwt);
    expect(payload.vc.credentialStatus).toMatchObject(status);
  });
});
