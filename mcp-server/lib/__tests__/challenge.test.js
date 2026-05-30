/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  generateChallenge,
  isChallengeExpired,
  signingInput,
  verifyChallengeResponse
} from '../core/challenge.js';

const {generateKeyPair, sign, toBase64url} = await import('../core/crypto.js');

/** @typedef {import("../core/crypto.js").KeyPair} KeyPair */

describe('generateChallenge', () => {
  it('creates a token with the given agentDid', () => {
    const token = generateChallenge('did:key:z6MkAgent');
    expect(token.agentDid).toBe('did:key:z6MkAgent');
    expect(typeof token.nonce).toBe('string');
    expect(token.nonce.length).toBeGreaterThan(0);
    expect(token.issuedAt).toBeLessThanOrEqual(
      Math.floor(Date.now() / 1000) + 1
    );
    expect(token.expiresAt).toBeGreaterThan(token.issuedAt);
  });

  it('uses default TTL of 300s', () => {
    const token = generateChallenge('did:key:z6MkAgent');
    expect(token.expiresAt - token.issuedAt).toBe(300);
  });

  it('respects custom TTL', () => {
    const token = generateChallenge('did:key:z6MkAgent', 60);
    expect(token.expiresAt - token.issuedAt).toBe(60);
  });

  it('generates unique nonces', () => {
    const t1 = generateChallenge('did:key:z6MkAgent');
    const t2 = generateChallenge('did:key:z6MkAgent');
    expect(t1.nonce).not.toBe(t2.nonce);
  });
});

describe('signingInput', () => {
  it('returns bytes of nonce:agentDid:issuedAt', () => {
    const token = {
      nonce: 'abc', agentDid: 'did:key:z6Mk', issuedAt: 1000, expiresAt: 1300
    };
    const bytes = signingInput(token);
    const str = new TextDecoder().decode(bytes);
    expect(str).toBe('abc:did:key:z6Mk:1000');
  });
});

describe('isChallengeExpired', () => {
  it('returns false when within TTL', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = {
      nonce: 'x', agentDid: 'd', issuedAt: now, expiresAt: now + 300
    };
    expect(isChallengeExpired(token)).toBe(false);
  });

  it('returns true when past expiresAt', () => {
    const token = {nonce: 'x', agentDid: 'd', issuedAt: 100, expiresAt: 200};
    expect(isChallengeExpired(token, 300)).toBe(true);
  });

  it('returns true when exactly at expiresAt', () => {
    const token = {nonce: 'x', agentDid: 'd', issuedAt: 100, expiresAt: 200};
    expect(isChallengeExpired(token, 200)).toBe(true);
  });
});

describe('verifyChallengeResponse', () => {
  /** @type {KeyPair} */
  let kp;

  beforeEach(async () => {
    kp = await generateKeyPair();
  });

  it('returns valid for correct signature within TTL', async () => {
    const token = generateChallenge('did:key:z6MkAgent');
    const sigBytes = await sign(signingInput(token), kp.privateKey);
    const sigB64 = toBase64url(sigBytes);
    const result = await verifyChallengeResponse(token, sigB64, kp.publicKey);
    expect(result.valid).toBe(true);
  });

  it('returns invalid for wrong key', async () => {
    const token = generateChallenge('did:key:z6MkAgent');
    const sigBytes = await sign(signingInput(token), kp.privateKey);
    const sigB64 = toBase64url(sigBytes);
    const wrongKp = await generateKeyPair();
    const result = await verifyChallengeResponse(
      token, sigB64, wrongKp.publicKey
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/signature/i);
  });

  it('returns invalid for expired token', async () => {
    const token = {nonce: 'n', agentDid: 'd', issuedAt: 100, expiresAt: 200};
    const sigBytes = await sign(signingInput(token), kp.privateKey);
    const sigB64 = toBase64url(sigBytes);
    const result = await verifyChallengeResponse(
      token, sigB64, kp.publicKey, 300
    );
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/expired/i);
  });

  it('returns invalid for tampered signing input', async () => {
    const token = generateChallenge('did:key:z6MkAgent');
    const tampered = new TextEncoder().encode('wrong:input:0');
    const sigBytes = await sign(tampered, kp.privateKey);
    const sigB64 = toBase64url(sigBytes);
    const result = await verifyChallengeResponse(token, sigB64, kp.publicKey);
    expect(result.valid).toBe(false);
  });
});
