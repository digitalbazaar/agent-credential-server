/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure crypto utilities for Ed25519 keys, signing, and verification.
 * No IO — testable in isolation.
 *
 * The multikey surface (generateMultikey, publicKeyBytesFromMultibase) is the
 * primary, DB-stack-native path built on ed25519-multikey. The raw-bytes
 * bridge (generateKeyPair, sign, verify) preserves the legacy Uint8Array key
 * API that the still-JWT-based vc.js, chain.js, and challenge.js depend on.
 * The bridge is re-based on multikey except for one Ed25519 seed-to-public-key
 * derivation in sign(), which the DB libraries do not expose; that single
 * noble call is marked for removal once the JWT signing path retires.
 */
import * as base58 from 'base58-universal';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';

// Ed25519 public-key multicodec prefix (varint 0xed 0x01).
const ED25519_PUB_PREFIX = new Uint8Array([0xed, 0x01]);

/**
 * @typedef {object} KeyPair
 * @property {Uint8Array} privateKey The 32-byte Ed25519 seed.
 * @property {Uint8Array} publicKey The 32-byte Ed25519 public key.
 */

/**
 * An @digitalbazaar/ed25519-multikey key pair instance.
 *
 * @typedef {Awaited<ReturnType<typeof Ed25519Multikey.generate>>} Multikey
 */

/**
 * Generate a multikey-native Ed25519 key pair.
 *
 * @returns {Promise<Multikey>} A multikey with signer()/verifier() and
 *   publicKeyMultibase, as consumed by the DB Data Integrity stack.
 */
export async function generateMultikey() {
  return Ed25519Multikey.generate();
}

/**
 * Decode an Ed25519 publicKeyMultibase to its raw 32-byte public key.
 *
 * @param {string} multibase - A z-prefixed base58btc Ed25519 multikey.
 * @returns {Promise<Uint8Array>} The raw 32-byte public key.
 */
export async function publicKeyBytesFromMultibase(multibase) {
  const key = await Ed25519Multikey.from({publicKeyMultibase: multibase});
  const {publicKey} = await key.export({publicKey: true, raw: true});
  if(!publicKey) {
    throw new Error('Multikey export did not return a public key.');
  }
  // normalize Buffer → plain Uint8Array so callers see a consistent type
  return new Uint8Array(publicKey);
}

/**
 * Encode a raw 32-byte Ed25519 public key as a z-prefixed multibase string.
 *
 * @param {Uint8Array} publicKey - The raw 32-byte public key.
 * @returns {string} The z-prefixed base58btc multikey string.
 */
function publicKeyMultibaseFromBytes(publicKey) {
  const prefixed = new Uint8Array(ED25519_PUB_PREFIX.length + publicKey.length);
  prefixed.set(ED25519_PUB_PREFIX);
  prefixed.set(publicKey, ED25519_PUB_PREFIX.length);
  return `z${base58.encode(prefixed)}`;
}

/**
 * Generate a raw-bytes Ed25519 key pair (legacy bridge).
 *
 * @returns {Promise<KeyPair>} The 32-byte seed and 32-byte public key.
 */
export async function generateKeyPair() {
  const key = await Ed25519Multikey.generate();
  const {publicKey, secretKey} = await key.export({
    publicKey: true,
    secretKey: true,
    raw: true
  });
  if(!publicKey || !secretKey) {
    throw new Error('Multikey export did not return raw key bytes.');
  }
  // multikey's raw secret is seed(32) || publicKey(32); the seed is the
  // 32-byte private key the legacy API exposes. Normalize Buffer → plain
  // Uint8Array so callers see a consistent type.
  return {
    privateKey: new Uint8Array(secretKey.slice(0, 32)),
    publicKey: new Uint8Array(publicKey)
  };
}

/**
 * Sign a payload with a raw 32-byte Ed25519 seed (legacy bridge).
 *
 * @param {Uint8Array} payload - The bytes to sign.
 * @param {Uint8Array} privateKey - The 32-byte Ed25519 seed.
 * @returns {Promise<Uint8Array>} The 64-byte signature.
 */
export async function sign(payload, privateKey) {
  // Ed25519 seed → public key derivation is not exposed by the DB libraries;
  // this single @noble call is the only legacy dependency here and is removed
  // when the JWT signing path retires.
  const {getPublicKeyAsync} = await import('@noble/ed25519');
  const {sha512} = await import('@noble/hashes/sha2.js');
  const ed = await import('@noble/ed25519');
  ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
  const publicKey = await getPublicKeyAsync(privateKey);

  const jwk = {
    kty: 'OKP',
    crv: 'Ed25519',
    x: toBase64url(publicKey),
    d: toBase64url(privateKey)
  };
  const key = await Ed25519Multikey.fromJwk({jwk, secretKey: true});
  return key.signer().sign({data: payload});
}

/**
 * Verify an Ed25519 signature against a raw 32-byte public key (legacy bridge).
 *
 * @param {Uint8Array} payload - The bytes that were signed.
 * @param {Uint8Array} signature - The signature to check.
 * @param {Uint8Array} publicKey - The raw 32-byte public key.
 * @returns {Promise<boolean>} True if the signature is valid.
 */
export async function verify(payload, signature, publicKey) {
  try {
    const multibase = publicKeyMultibaseFromBytes(publicKey);
    const key = await Ed25519Multikey.from({publicKeyMultibase: multibase});
    return await key.verifier().verify({data: payload, signature});
  } catch {
    return false;
  }
}

/**
 * @param {Uint8Array} bytes - The bytes to encode.
 * @returns {string} The base64url-encoded string.
 */
export function toBase64url(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * @param {string} str - The base64url-encoded string.
 * @returns {Uint8Array} The decoded bytes.
 */
export function fromBase64url(str) {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(base64, 'base64'));
}
