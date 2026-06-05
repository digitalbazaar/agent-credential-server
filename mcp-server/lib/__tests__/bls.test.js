/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  BLS_MULTIKEY_HEADER, BLS_SD_ALGORITHM, generateBlsMultikey, importBlsMultikey
} from '../core/bls.js';

describe('generateBlsMultikey', () => {
  it('generates a BLS12-381 multikey with a zUC7 publicKeyMultibase',
    async () => {
      const key = await generateBlsMultikey();
      expect(key.publicKeyMultibase).toMatch(/^zUC7/);
      expect(key.secretKeyMultibase).toEqual(expect.any(String));
    });

  it('produces a working BBS signer', async () => {
    const key = await generateBlsMultikey();
    const signer = key.signer();
    expect(typeof signer.sign).toBe('function');
  });

  it('generates a fresh key each call', async () => {
    const a = await generateBlsMultikey();
    const b = await generateBlsMultikey();
    expect(a.publicKeyMultibase).not.toEqual(b.publicKeyMultibase);
  });
});

describe('importBlsMultikey', () => {
  it('round-trips a generated key by its multibase pair', async () => {
    const key = await generateBlsMultikey();
    const exported = await key.export({publicKey: true, secretKey: true});
    const imported = await importBlsMultikey(exported);
    expect(imported.publicKeyMultibase).toEqual(key.publicKeyMultibase);
  });

  it('rejects a non-BLS (Ed25519) multikey header', async () => {
    await expect(importBlsMultikey({
      publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    })).rejects.toThrow();
  });

  it('rejects a P-256 ECDSA multikey header', async () => {
    await expect(importBlsMultikey({
      publicKeyMultibase: 'zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169'
    })).rejects.toThrow();
  });
});

describe('constants', () => {
  it('BLS_MULTIKEY_HEADER is the BLS12-381 did:key prefix', () => {
    expect(BLS_MULTIKEY_HEADER).toBe('zUC7');
  });
  it('BLS_SD_ALGORITHM is the bbs-2023 required algorithm', () => {
    expect(BLS_SD_ALGORITHM).toBe('BBS-BLS12-381-SHA-256');
  });
});
