/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {fromBase64url} from '../core/crypto.js';
import {makeDocumentLoader} from './didKeyContext.js';
import {verifyCredentialDI} from '../core/vc.js';

/**
 * @typedef {import("../core/vc.js").VerifyDIResult} VerifyDIResult
 * @typedef {import("../core/vc.js").DataIntegrityCredential}
 *   DataIntegrityCredential
 * @typedef {import("../core/resolver.js").VerificationMethod}
 *   VerificationMethod
 */

/**
 * Verify a VC 2.0 Data Integrity credential. The issuer DID is resolved by the
 * document loader (offline for did:key), so the proof is checked against the
 * issuer's published key.
 *
 * @param {DataIntegrityCredential} credential - The credential to verify.
 * @returns {Promise<VerifyDIResult>} The verification result.
 */
export async function verifyCredentialTool(credential) {
  return verifyCredentialDI({credential, documentLoader: makeDocumentLoader()});
}

/**
 * Extract Ed25519 public key bytes from verification methods.
 * Supports publicKeyJwk (crv: Ed25519) and publicKeyMultibase (z-prefix
 * base58btc).
 *
 * @param {VerificationMethod[]} methods - Verification methods to search.
 * @returns {Uint8Array | null} The Ed25519 public key bytes, or null if none.
 */
export function extractEd25519Key(methods) {
  for(const method of methods) {
    // JWK format
    if(
      method.publicKeyJwk &&
      method.publicKeyJwk.crv === 'Ed25519' &&
      typeof method.publicKeyJwk.x === 'string'
    ) {
      return fromBase64url(method.publicKeyJwk.x);
    }

    // Multibase (z = base58btc) — Ed25519 public key multicodec prefix is
    // 0xed 0x01
    if(method.publicKeyMultibase && method.publicKeyMultibase.startsWith('z')) {
      const raw = base58Decode(method.publicKeyMultibase.slice(1));
      if(raw && raw.length >= 2) {
        return raw.slice(2); // strip multicodec prefix
      }
    }
  }
  return null;
}

/**
 * Minimal base58btc decoder (Bitcoin alphabet).
 *
 * @param {string} encoded - The base58btc-encoded string to decode.
 * @returns {Uint8Array | null} The decoded bytes, or null if invalid.
 */
function base58Decode(encoded) {
  const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let n = BigInt(0);
  for(const ch of encoded) {
    const idx = ALPHABET.indexOf(ch);
    if(idx < 0) {
      return null;
    }
    n = n * BigInt(58) + BigInt(idx);
  }
  // Convert bigint to bytes
  const hex = n.toString(16).padStart(2, '0');
  const padded = hex.length % 2 ? '0' + hex : hex;
  const bytes = new Uint8Array(padded.length / 2);
  for(let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(padded.slice(i * 2, i * 2 + 2), 16);
  }
  // Prepend leading zero bytes for leading '1's
  let leading = 0;
  for(const ch of encoded) {
    if(ch === '1') {
      leading++;
    } else {
      break;
    }
  }
  const result = new Uint8Array(leading + bytes.length);
  result.set(bytes, leading);
  return result;
}
