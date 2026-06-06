/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  BLS_MULTIKEY_HEADERS, BLS_SD_ALGORITHM, generateBlsMultikey, importBlsMultikey
} from '../core/bls.js';

describe('generateBlsMultikey', () => {
  it('generates a multikey whose publicKeyMultibase uses a valid G2 prefix',
    async () => {
      // generate several: the 4th char of a G2 key varies (zUC6/zUC7), so a
      // single sample could mask the variability that broke CI
      for(let i = 0; i < 12; i++) {
        const key = await generateBlsMultikey();
        const prefix = key.publicKeyMultibase.slice(0, 4);
        expect(BLS_MULTIKEY_HEADERS).toContain(prefix);
        expect(key.secretKeyMultibase).toEqual(expect.any(String));
      }
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
  it('BLS_MULTIKEY_HEADERS are the two BLS12-381 G2 did:key prefixes', () => {
    expect(BLS_MULTIKEY_HEADERS).toEqual(['zUC6', 'zUC7']);
  });
  it('BLS_SD_ALGORITHM is the bbs-2023 required algorithm', () => {
    expect(BLS_SD_ALGORITHM).toBe('BBS-BLS12-381-SHA-256');
  });
});
