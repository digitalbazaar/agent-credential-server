/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * StatusList2021 revocation checking. Pure (takes already-fetched data).
 */
import { gunzipSync } from "node:zlib";

/**
 * @param {string} encodedList
 * @returns {Uint8Array}
 */
export function decodeStatusList(encodedList) {
  // base64url → Buffer → gunzip
  const compressed = Buffer.from(encodedList, "base64url");
  const decompressed = gunzipSync(compressed);
  return new Uint8Array(decompressed);
}

/**
 * @param {Uint8Array} decoded
 * @param {number} index
 * @returns {boolean}
 */
export function isRevoked(decoded, index) {
  const byteIndex = Math.floor(index / 8);
  if (byteIndex >= decoded.length) return false;
  const bitIndex = 7 - (index % 8); // MSB first
  return (decoded[byteIndex] & (1 << bitIndex)) !== 0;
}

/**
 * @param {string} encodedList
 * @param {string} indexStr
 * @returns {{revoked: boolean, reason?: string}}
 */
export function checkRevocationStatus(encodedList, indexStr) {
  const decoded = decodeStatusList(encodedList);
  const index = parseInt(indexStr, 10);
  const revoked = isRevoked(decoded, index);
  if (revoked) {
    return { revoked: true, reason: `Credential at index ${index} has been revoked` };
  }
  return { revoked: false };
}
