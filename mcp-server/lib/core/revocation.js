/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * StatusList2021 revocation checking. Pure (takes already-fetched data).
 *
 * Delegates the bitstring codec to @digitalbazaar/vc-status-list (the DB
 * canonical implementation) so we read exactly the encoding DB issuers
 * produce: base64url + gzip, MSB-first (left-to-right) bit indexing. We keep
 * a thin lenient wrapper so an out-of-range index is treated as not-revoked
 * instead of throwing.
 */
import {decodeList} from '@digitalbazaar/vc-status-list';

/**
 * @typedef {object} StatusList
 * @property {number} length - The number of bits in the list.
 * @property {(index: number) => boolean} getStatus - Reads the bit at index.
 */

/**
 * Decode a StatusList2021 encoded list into a StatusList instance.
 *
 * @param {string} encodedList - The base64url-encoded, gzipped status list.
 * @returns {Promise<StatusList>} The decoded status list.
 */
export async function decodeStatusList(encodedList) {
  return decodeList({encodedList});
}

/**
 * @param {StatusList} list - A decoded status list.
 * @param {number} index - The status list index to check.
 * @returns {boolean} True if the bit at the given index is set (revoked).
 *   Out-of-range indexes are treated as not-revoked.
 */
export function isRevoked(list, index) {
  if(index < 0 || index >= list.length) {
    return false;
  }
  return list.getStatus(index) === true;
}

/**
 * @typedef {object} RevocationResult
 * @property {boolean} revoked - Whether the credential is revoked.
 * @property {string} [reason] - A human-readable reason when revoked.
 */

/**
 * @param {string} encodedList - The base64url-encoded, gzipped status list.
 * @param {string} indexStr - The status list index, as a string.
 * @returns {Promise<RevocationResult>} The revocation result.
 */
export async function checkRevocationStatus(encodedList, indexStr) {
  const list = await decodeStatusList(encodedList);
  const index = parseInt(indexStr, 10);
  const revoked = isRevoked(list, index);
  if(revoked) {
    return {
      revoked: true,
      reason: `Credential at index ${index} has been revoked`
    };
  }
  return {revoked: false};
}
