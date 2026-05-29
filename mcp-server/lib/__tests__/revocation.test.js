/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { decodeStatusList, isRevoked, checkRevocationStatus } from "../core/revocation.js";
import { gzipSync } from "node:zlib";

/**
 * @param {number[]} revokedIndexes
 * @param {number} [totalBits=16384]
 * @returns {string}
 */
function makeEncodedList(revokedIndexes, totalBits = 16384) {
  const bytes = new Uint8Array(Math.ceil(totalBits / 8));
  for (const idx of revokedIndexes) {
    const byteIndex = Math.floor(idx / 8);
    const bitIndex = 7 - (idx % 8); // MSB first
    bytes[byteIndex] |= 1 << bitIndex;
  }
  const compressed = gzipSync(Buffer.from(bytes));
  return Buffer.from(compressed).toString("base64url");
}

describe("decodeStatusList", () => {
  it("decodes a gzip+base64url encoded status list", () => {
    const encoded = makeEncodedList([]);
    const decoded = decodeStatusList(encoded);
    expect(decoded).toBeInstanceOf(Uint8Array);
    expect(decoded.length).toBeGreaterThan(0);
  });

  it("throws on invalid base64url", () => {
    expect(() => decodeStatusList("!!!invalid!!!")).toThrow();
  });
});

describe("isRevoked", () => {
  it("returns false when bit is 0", () => {
    const encoded = makeEncodedList([]); // no bits set
    const decoded = decodeStatusList(encoded);
    expect(isRevoked(decoded, 0)).toBe(false);
    expect(isRevoked(decoded, 100)).toBe(false);
  });

  it("returns true when bit is set", () => {
    const encoded = makeEncodedList([5, 42]);
    const decoded = decodeStatusList(encoded);
    expect(isRevoked(decoded, 5)).toBe(true);
    expect(isRevoked(decoded, 42)).toBe(true);
  });

  it("returns false for unset neighbor bits", () => {
    const encoded = makeEncodedList([5]);
    const decoded = decodeStatusList(encoded);
    expect(isRevoked(decoded, 4)).toBe(false);
    expect(isRevoked(decoded, 6)).toBe(false);
  });

  it("returns false for out-of-range index", () => {
    const encoded = makeEncodedList([]);
    const decoded = decodeStatusList(encoded);
    expect(isRevoked(decoded, 9999999)).toBe(false);
  });
});

describe("checkRevocationStatus", () => {
  it("returns not revoked when bit clear", () => {
    const encoded = makeEncodedList([]);
    const result = checkRevocationStatus(encoded, "10");
    expect(result.revoked).toBe(false);
  });

  it("returns revoked when bit set", () => {
    const encoded = makeEncodedList([10]);
    const result = checkRevocationStatus(encoded, "10");
    expect(result.revoked).toBe(true);
    expect(result.reason).toMatch(/revoked/i);
  });

  it("returns revoked with reason for index 0", () => {
    const encoded = makeEncodedList([0]);
    const result = checkRevocationStatus(encoded, "0");
    expect(result.revoked).toBe(true);
  });

  it("handles invalid encodedList", () => {
    expect(() => checkRevocationStatus("not-valid-gzip", "0")).toThrow();
  });
});
