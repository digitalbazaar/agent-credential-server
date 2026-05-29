/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { extractEd25519Key } from "../tools/verify.js";
import { generateKeyPair, toBase64url } from "../core/crypto.js";

describe("extractEd25519Key", () => {
  it("extracts key from publicKeyJwk (Ed25519)", async () => {
    const { publicKey } = await generateKeyPair();
    const methods = [
      {
        id: "did:key:z#key-1",
        type: "JsonWebKey2020",
        controller: "did:key:z",
        publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: toBase64url(publicKey) },
      },
    ];
    const result = extractEd25519Key(methods);
    expect(result).not.toBeNull();
    expect(result).toEqual(publicKey);
  });

  it("returns null for publicKeyJwk with wrong crv", async () => {
    const methods = [
      {
        id: "did:key:z#key-1",
        type: "JsonWebKey2020",
        controller: "did:key:z",
        publicKeyJwk: { kty: "EC", crv: "P-256", x: "somekey" },
      },
    ];
    expect(extractEd25519Key(methods)).toBeNull();
  });

  it("extracts key from publicKeyMultibase (z-prefix base58btc with multicodec)", async () => {
    const { publicKey } = await generateKeyPair();
    // Construct a valid multibase: multicodec prefix 0xed 0x01 + raw public key, base58btc encoded
    const withPrefix = new Uint8Array([0xed, 0x01, ...publicKey]);
    const encoded = "z" + base58btcEncode(withPrefix);
    const methods = [
      {
        id: "did:key:z#key-1",
        type: "Ed25519VerificationKey2020",
        controller: "did:key:z",
        publicKeyMultibase: encoded,
      },
    ];
    const result = extractEd25519Key(methods);
    expect(result).not.toBeNull();
    expect(result).toEqual(publicKey);
  });

  it("returns null when no verification methods present", () => {
    expect(extractEd25519Key([])).toBeNull();
  });

  it("returns null when method has no recognized key format", () => {
    const methods = [
      {
        id: "did:key:z#key-1",
        type: "RsaVerificationKey2018",
        controller: "did:key:z",
        publicKeyBase58: "somersakey",
      },
    ];
    expect(extractEd25519Key(methods)).toBeNull();
  });

  it("skips non-z multibase prefix", () => {
    const methods = [
      {
        id: "did:key:z#key-1",
        type: "Ed25519VerificationKey2020",
        controller: "did:key:z",
        publicKeyMultibase: "uaGVsbG8", // 'u' prefix = base64url, not base58btc
      },
    ];
    expect(extractEd25519Key(methods)).toBeNull();
  });
});

/**
 * Base58btc encoder (Bitcoin alphabet) — mirrors the decoder in verify.js
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function base58btcEncode(bytes) {
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let n = BigInt(0);
  for (const b of bytes) {
    n = n * BigInt(256) + BigInt(b);
  }
  let result = "";
  while (n > BigInt(0)) {
    result = ALPHABET[Number(n % BigInt(58))] + result;
    n = n / BigInt(58);
  }
  for (const b of bytes) {
    if (b === 0) result = "1" + result;
    else break;
  }
  return result;
}
