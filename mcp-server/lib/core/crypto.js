/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Pure crypto utilities: key generation, signing, verification (Ed25519).
 * No IO — testable in isolation.
 */
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";

// noble/ed25519 v2 requires sha512 to be set
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));

/**
 * @typedef {object} KeyPair
 * @property {Uint8Array} privateKey
 * @property {Uint8Array} publicKey
 */

/**
 * @returns {Promise<KeyPair>}
 */
export async function generateKeyPair() {
  const privateKey = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

/**
 * @param {Uint8Array} payload
 * @param {Uint8Array} privateKey
 * @returns {Promise<Uint8Array>}
 */
export async function sign(payload, privateKey) {
  return ed.signAsync(payload, privateKey);
}

/**
 * @param {Uint8Array} payload
 * @param {Uint8Array} signature
 * @param {Uint8Array} publicKey
 * @returns {Promise<boolean>}
 */
export async function verify(payload, signature, publicKey) {
  try {
    return await ed.verifyAsync(signature, payload, publicKey);
  } catch {
    return false;
  }
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toBase64url(bytes) {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/**
 * @param {string} str
 * @returns {Uint8Array}
 */
export function fromBase64url(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  return new Uint8Array(Buffer.from(base64, "base64"));
}
