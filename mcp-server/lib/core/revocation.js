/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * StatusList2021 revocation checking. Pure (takes already-fetched data).
 */
import {gunzipSync} from 'node:zlib';

/**
 * @param {string} encodedList - The base64url-encoded, gzipped status list.
 * @returns {Uint8Array} The decompressed status list bytes.
 */
export function decodeStatusList(encodedList) {
  // base64url → Buffer → gunzip
  const compressed = Buffer.from(encodedList, 'base64url');
  const decompressed = gunzipSync(compressed);
  return new Uint8Array(decompressed);
}

/**
 * @param {Uint8Array} decoded - The decompressed status list bytes.
 * @param {number} index - The status list index to check.
 * @returns {boolean} True if the bit at the given index is set (revoked).
 */
export function isRevoked(decoded, index) {
  const byteIndex = Math.floor(index / 8);
  if(byteIndex >= decoded.length) {
    return false;
  }
  const bitIndex = 7 - (index % 8); // MSB first
  return (decoded[byteIndex] & (1 << bitIndex)) !== 0;
}

/**
 * @param {string} encodedList - The base64url-encoded, gzipped status list.
 * @param {string} indexStr - The status list index, as a string.
 * @returns {{revoked: boolean, reason?: string}} The revocation result.
 */
export function checkRevocationStatus(encodedList, indexStr) {
  const decoded = decodeStatusList(encodedList);
  const index = parseInt(indexStr, 10);
  const revoked = isRevoked(decoded, index);
  if(revoked) {
    return {
      revoked: true,
      reason: `Credential at index ${index} has been revoked`
    };
  }
  return {revoked: false};
}
