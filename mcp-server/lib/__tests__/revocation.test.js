/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {
  checkRevocationStatus, decodeStatusList, isRevoked
} from '../core/revocation.js';
import {createList} from '@digitalbazaar/vc-status-list';

/**
 * Build a StatusList2021 encoded bitstring using the DB canonical library, so
 * the fixture matches exactly what a real DB issuer produces (base64url+gzip,
 * MSB-first indexing).
 *
 * @param {number[]} revokedIndexes - Bit positions to mark as revoked.
 * @param {number} [length=16384] - Total bitstring length in bits.
 * @returns {Promise<string>} The encoded status list.
 */
async function makeEncodedList(revokedIndexes, length = 16384) {
  const list = await createList({length});
  for(const idx of revokedIndexes) {
    list.setStatus(idx, true);
  }
  return list.encode();
}

describe('decodeStatusList', () => {
  it('decodes a gzip+base64url encoded status list', async () => {
    const encoded = await makeEncodedList([]);
    const list = await decodeStatusList(encoded);
    expect(typeof list.getStatus).toBe('function');
    expect(list.length).toBeGreaterThan(0);
  });

  it('rejects on invalid encoded input', async () => {
    await expect(decodeStatusList('!!!invalid!!!')).rejects.toThrow();
  });
});

describe('isRevoked', () => {
  it('returns false when bit is 0', async () => {
    const encoded = await makeEncodedList([]); // no bits set
    const list = await decodeStatusList(encoded);
    expect(isRevoked(list, 0)).toBe(false);
    expect(isRevoked(list, 100)).toBe(false);
  });

  it('returns true when bit is set', async () => {
    const encoded = await makeEncodedList([5, 42]);
    const list = await decodeStatusList(encoded);
    expect(isRevoked(list, 5)).toBe(true);
    expect(isRevoked(list, 42)).toBe(true);
  });

  it('returns false for unset neighbor bits', async () => {
    const encoded = await makeEncodedList([5]);
    const list = await decodeStatusList(encoded);
    expect(isRevoked(list, 4)).toBe(false);
    expect(isRevoked(list, 6)).toBe(false);
  });

  it('returns false for out-of-range index', async () => {
    const encoded = await makeEncodedList([]);
    const list = await decodeStatusList(encoded);
    expect(isRevoked(list, 9999999)).toBe(false);
  });

  it('returns false for negative index', async () => {
    const encoded = await makeEncodedList([]);
    const list = await decodeStatusList(encoded);
    expect(isRevoked(list, -1)).toBe(false);
  });
});

describe('checkRevocationStatus', () => {
  it('returns not revoked when bit clear', async () => {
    const encoded = await makeEncodedList([]);
    const result = await checkRevocationStatus(encoded, '10');
    expect(result.revoked).toBe(false);
  });

  it('returns revoked when bit set', async () => {
    const encoded = await makeEncodedList([10]);
    const result = await checkRevocationStatus(encoded, '10');
    expect(result.revoked).toBe(true);
    expect(result.reason).toMatch(/revoked/i);
  });

  it('returns revoked with reason for index 0', async () => {
    const encoded = await makeEncodedList([0]);
    const result = await checkRevocationStatus(encoded, '0');
    expect(result.revoked).toBe(true);
  });

  it('handles invalid encodedList', async () => {
    await expect(checkRevocationStatus('not-valid-gzip', '0'))
      .rejects.toThrow();
  });
});
