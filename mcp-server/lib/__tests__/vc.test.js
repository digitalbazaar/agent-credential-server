/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  issueCredential, parseCredential, verifyCredentialJwt
} from '../core/vc.js';
import {generateKeyPair} from '../core/crypto.js';

const ISSUER_DID = 'did:key:z6MkHuman';
const AGENT_DID = 'did:key:z6MkAgent';

describe('VC: issue + verify', () => {
  it('issues a valid credential and verifies it', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID,
      {age_verified: true, over_21: true},
      ISSUER_DID,
      kp
    );
    expect(vc.jwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);

    const result = await verifyCredentialJwt(vc.jwt, kp.publicKey);
    expect(result.valid).toBe(true);
    expect(result.issuer).toBe(ISSUER_DID);
    expect(result.subject).toBe(AGENT_DID);
    expect(result.claims).toMatchObject({age_verified: true, over_21: true});
  });

  it('rejects a tampered credential', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {over_21: true}, ISSUER_DID, kp
    );

    // tamper: replace body with different claims
    const parts = vc.jwt.split('.');
    const fakeBody = Buffer.from(
      JSON.stringify({
        iss: ISSUER_DID,
        sub: AGENT_DID,
        iat: 0,
        vc: {credentialSubject: {id: AGENT_DID, over_21: false}}
      })
    ).toString('base64url');
    const tampered = `${parts[0]}.${fakeBody}.${parts[2]}`;

    const result = await verifyCredentialJwt(tampered, kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it('rejects an expired credential', async () => {
    const kp = await generateKeyPair();
    // expire immediately (1 second TTL, then wait is not needed —
    // use negative TTL trick)
    const vc = await issueCredential(
      AGENT_DID, {over_21: true}, ISSUER_DID, kp, -1
    );

    const result = await verifyCredentialJwt(vc.jwt, kp.publicKey);
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  it('parseCredential extracts payload', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {age_verified: true}, ISSUER_DID, kp
    );
    const payload = parseCredential(vc.jwt);
    expect(payload?.iss).toBe(ISSUER_DID);
    expect(payload?.sub).toBe(AGENT_DID);
  });

  it('parseCredential returns null for malformed JWT', () => {
    expect(parseCredential('not.a.valid.jwt.extra')).toBeNull();
    expect(parseCredential('onlytwoparts.nope')).toBeNull();
  });
});

describe('VC: audience restriction', () => {
  const RESOURCE_SERVER = 'did:web:resource.example.com';

  it('issues VC with audience and parses aud field', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {role: 'admin'}, ISSUER_DID, kp, undefined,
      {audience: RESOURCE_SERVER}
    );
    const payload = parseCredential(vc.jwt);
    expect(payload?.aud).toBe(RESOURCE_SERVER);
  });

  it('issues VC with array audience', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {}, ISSUER_DID, kp, undefined,
      {audience: [RESOURCE_SERVER, 'did:web:other.example.com']}
    );
    const payload = parseCredential(vc.jwt);
    const aud = /** @type {string[]} */ (payload?.aud);
    expect(Array.isArray(aud)).toBe(true);
    expect(aud.includes(RESOURCE_SERVER)).toBe(true);
  });

  it('verifies with matching expectedAudience', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {}, ISSUER_DID, kp, undefined, {audience: RESOURCE_SERVER}
    );
    const result = await verifyCredentialJwt(
      vc.jwt, kp.publicKey, RESOURCE_SERVER
    );
    expect(result.valid).toBe(true);
  });

  it('rejects with mismatched expectedAudience', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {}, ISSUER_DID, kp, undefined, {audience: RESOURCE_SERVER}
    );
    const result = await verifyCredentialJwt(
      vc.jwt, kp.publicKey, 'did:web:wrong.example.com'
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/audience/i);
  });

  it('rejects when expectedAudience set but VC has no aud', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(AGENT_DID, {}, ISSUER_DID, kp);
    const result = await verifyCredentialJwt(
      vc.jwt, kp.publicKey, RESOURCE_SERVER
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/audience/i);
  });

  it('does not check audience when expectedAudience is not set', async () => {
    const kp = await generateKeyPair();
    const vc = await issueCredential(
      AGENT_DID, {}, ISSUER_DID, kp, undefined, {audience: RESOURCE_SERVER}
    );
    // no expectedAudience
    const result = await verifyCredentialJwt(vc.jwt, kp.publicKey);
    expect(result.valid).toBe(true);
  });
});
