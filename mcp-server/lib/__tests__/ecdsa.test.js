/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  ECDSA_MULTIKEY_HEADER, generateEcdsaMultikey, importEcdsaMultikey
} from '../core/ecdsa.js';

describe('generateEcdsaMultikey', () => {
  it('generates a P-256 multikey with a zDna publicKeyMultibase', async () => {
    const key = await generateEcdsaMultikey();
    expect(key.publicKeyMultibase).toMatch(/^zDna/);
    expect(key.secretKeyMultibase).toEqual(expect.any(String));
  });

  it('produces a working signer over P-256', async () => {
    const key = await generateEcdsaMultikey();
    const signer = key.signer();
    expect(typeof signer.sign).toBe('function');
    const sig = await signer.sign({data: new Uint8Array([1, 2, 3])});
    expect(sig).toBeInstanceOf(Uint8Array);
    expect(sig.length).toBeGreaterThan(0);
  });

  it('generates a fresh key each call', async () => {
    const a = await generateEcdsaMultikey();
    const b = await generateEcdsaMultikey();
    expect(a.publicKeyMultibase).not.toEqual(b.publicKeyMultibase);
  });
});

describe('importEcdsaMultikey', () => {
  it('round-trips a generated key by its multibase pair', async () => {
    const key = await generateEcdsaMultikey();
    const exported = await key.export({publicKey: true, secretKey: true});
    const imported = await importEcdsaMultikey(exported);
    expect(imported.publicKeyMultibase).toEqual(key.publicKeyMultibase);
  });

  it('imports a public-only multikey (no signer)', async () => {
    const key = await generateEcdsaMultikey();
    const imported = await importEcdsaMultikey({
      publicKeyMultibase: key.publicKeyMultibase
    });
    expect(imported.publicKeyMultibase).toEqual(key.publicKeyMultibase);
  });

  it('rejects a non-P-256 (Ed25519) multikey header', async () => {
    // an Ed25519 multikey starts z6Mk, not zDna — must not import as ECDSA
    await expect(importEcdsaMultikey({
      publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    })).rejects.toThrow();
  });
});

describe('ECDSA_MULTIKEY_HEADER', () => {
  it('is the P-256 did:key multibase prefix', () => {
    expect(ECDSA_MULTIKEY_HEADER).toBe('zDna');
  });
});
