/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  fromBase64url, generateKeyPair, generateMultikey,
  publicKeyBytesFromMultibase, sign, toBase64url, verify
} from '../core/crypto.js';

describe('crypto', () => {
  it('generates a keypair with correct key lengths', async () => {
    const kp = await generateKeyPair();
    expect(kp.privateKey).toHaveLength(32);
    expect(kp.publicKey).toHaveLength(32);
  });

  it('sign + verify roundtrip succeeds', async () => {
    const kp = await generateKeyPair();
    const msg = new TextEncoder().encode('hello world');
    const sig = await sign(msg, kp.privateKey);
    const ok = await verify(msg, sig, kp.publicKey);
    expect(ok).toBe(true);
  });

  it('verify fails for tampered payload', async () => {
    const kp = await generateKeyPair();
    const msg = new TextEncoder().encode('hello world');
    const sig = await sign(msg, kp.privateKey);
    const tampered = new TextEncoder().encode('hello world!');
    const ok = await verify(tampered, sig, kp.publicKey);
    expect(ok).toBe(false);
  });

  it('base64url encodes and decodes roundtrip', () => {
    const bytes = new Uint8Array([1, 2, 3, 255, 0, 128]);
    const encoded = toBase64url(bytes);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
    const decoded = fromBase64url(encoded);
    expect(decoded).toEqual(bytes);
  });
});

describe('crypto: multikey', () => {
  it('generates a multikey with a z-prefixed publicKeyMultibase', async () => {
    const mk = await generateMultikey();
    expect(typeof mk.publicKeyMultibase).toBe('string');
    expect(mk.publicKeyMultibase).toMatch(/^z6Mk/);
    expect(typeof mk.secretKeyMultibase).toBe('string');
  });

  it('signs and verifies a roundtrip via signer/verifier', async () => {
    const mk = await generateMultikey();
    const data = new TextEncoder().encode('hello multikey');
    const signature = await mk.signer().sign({data});
    expect(signature).toBeInstanceOf(Uint8Array);
    const ok = await mk.verifier().verify({data, signature});
    expect(ok).toBe(true);
  });

  it('fails verification for a tampered payload', async () => {
    const mk = await generateMultikey();
    const data = new TextEncoder().encode('hello multikey');
    const signature = await mk.signer().sign({data});
    const tampered = new TextEncoder().encode('hello multikey!');
    const ok = await mk.verifier().verify({data: tampered, signature});
    expect(ok).toBe(false);
  });

  it('decodes a public key multibase to raw 32 bytes', async () => {
    const mk = await generateMultikey();
    const bytes = await publicKeyBytesFromMultibase(mk.publicKeyMultibase);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes).toHaveLength(32);
  });

  it('decodes a public key that verifies a signer() signature', async () => {
    // the multibase-decoded public key must equal the raw public key the
    // legacy raw-bytes bridge expects: it should verify a signer() signature
    const mk = await generateMultikey();
    const fromMultibase = await publicKeyBytesFromMultibase(
      mk.publicKeyMultibase
    );
    const data = new TextEncoder().encode('cross-check');
    const signature = await mk.signer().sign({data});
    const ok = await verify(data, signature, fromMultibase);
    expect(ok).toBe(true);
  });
});
