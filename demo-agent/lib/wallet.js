/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The wallet seam — holder Model B for selective disclosure.
 *
 * The wallet holds the full SD credential (birthdate and all) in a closure and
 * exposes ONLY `requestDisclosure(claims)`, which returns a reveal document
 * disclosing just the requested claims. The agent calls this seam but cannot
 * read the full credential, so the birthdate and other hidden claims never
 * cross into agent-side code, output, or tool-call arguments (KYA-OS R-L3-5).
 * This is the software analog of an mDL wallet deriving a presentation and
 * handing the verifier only the disclosure.
 */
import {deriveDisclosureTool} from 'mcp-server/lib/tools/deriveDisclosure.js';

/**
 * @typedef {import('mcp-server/lib/core/vcSd.js').SdCryptosuite} SdCryptosuite
 */

/**
 * @typedef {object} Wallet
 * @property {(claims: string[]) => Promise<Record<string, unknown>>}
 *   requestDisclosure - Derive a reveal document disclosing only `claims`.
 * @property {SdCryptosuite} cryptosuite - The SD cryptosuite the held
 *   credential was issued under (so the verifier can match it).
 */

/**
 * Create a wallet that holds a full SD credential privately and derives minimal
 * disclosures on request. The credential is captured in a closure and is not
 * exposed as a property — the only way out is a derived reveal document.
 *
 * @param {Record<string, unknown>} credential - The full base SD credential.
 * @param {SdCryptosuite} [cryptosuite] - The SD cryptosuite the credential was
 *   issued under; defaults to ecdsa-sd-2023.
 * @returns {Wallet} The wallet seam.
 */
export function createWallet(credential, cryptosuite = 'ecdsa-sd-2023') {
  return Object.freeze({
    cryptosuite,
    requestDisclosure(claims) {
      return deriveDisclosureTool({
        credential, revealClaims: claims, cryptosuite
      });
    }
  });
}
