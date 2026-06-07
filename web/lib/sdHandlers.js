/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Selective-disclosure handlers for the web shell. These drive the holder
 * Model B flow server-side: a wallet holds the full SD credential (birthdate
 * and all), derives a minimal reveal document disclosing only the requested
 * claim, and the verifier checks the derived proof. Only the reveal document
 * and the verdict cross to the browser — the full credential never does
 * (KYA-OS R-L3-5). Framework-agnostic; unit-tests without HTTP.
 *
 * Two cryptosuites: ecdsa-sd-2023 (linkable) and bbs-2023 (unlinkable — two
 * derivations cannot be correlated). The UI uses this to show data
 * minimization and, for bbs-2023, non-correlation.
 */
import {
  buildSdAgeDisclosure, buildSdUnlinkableDisclosure
} from 'demo-agent/lib/scenarios.js';
import {sanitize} from './sanitize.js';
import {verifyDisclosureTool} from 'mcp-server/lib/tools/verifyDisclosure.js';

/**
 * @typedef {import('./handlers.js').HandlerResult} HandlerResult
 * @typedef {import('mcp-server/lib/core/vcSd.js').SdCryptosuite} SdCryptosuite
 */

// the claims the demo SD credential carries, for the wallet/verifier split
// visual. The values stay in the wallet; only this manifest of NAMES is shown,
// so the UI can say "5 claims held, 1 disclosed" without leaking values.
const HELD_CLAIM_NAMES = Object.freeze([
  'birthdate', 'age_over_18', 'age_over_21', 'age_over_65', 'name'
]);

// the SD cryptosuites the web demo exposes, keyed by the UI's mode name
/** @type {Record<string, {build: () => Promise<any>, cryptosuite: string}>} */
const SD_MODES = Object.freeze({
  linkable: {build: buildSdAgeDisclosure, cryptosuite: 'ecdsa-sd-2023'},
  unlinkable: {build: buildSdUnlinkableDisclosure, cryptosuite: 'bbs-2023'}
});

/**
 * Validate the disclosure-mode name. Returns the mode, or null if unknown.
 *
 * @param {string} mode - The UI mode name ('linkable' | 'unlinkable').
 * @returns {{build: () => Promise<any>, cryptosuite: string} | null} The mode.
 */
function resolveMode(mode) {
  return SD_MODES[mode] ?? null;
}

/**
 * Derive a reveal document for a mode, disclosing only the age flag. The full
 * credential stays in the server-side wallet; the response carries only the
 * reveal document, the names of the held and disclosed claims, and the
 * cryptosuite. The unlinkable mode derives twice, so the UI can show two
 * uncorrelated proofs from one credential.
 *
 * @param {string} mode - 'linkable' | 'unlinkable'.
 * @returns {Promise<HandlerResult>} The sanitized reveal(s), or a 404.
 */
export async function postDisclose(mode) {
  const resolved = resolveMode(mode);
  if(!resolved) {
    return {status: 404, body: {error: `Unknown disclosure mode "${mode}".`}};
  }

  const {wallet, agentDid, revealClaims} = await resolved.build();
  const reveal = await wallet.requestDisclosure(revealClaims);

  // a second derivation for the unlinkable mode, to show non-correlation
  const second = mode === 'unlinkable' ?
    await wallet.requestDisclosure(revealClaims) : null;

  const {value} = sanitize({
    mode,
    cryptosuite: resolved.cryptosuite,
    agentDid,
    heldClaims: HELD_CLAIM_NAMES,
    disclosedClaims: revealClaims,
    hiddenCount: HELD_CLAIM_NAMES.length - revealClaims.length,
    reveal,
    secondReveal: second
  });
  return {status: 200, body: value};
}

/**
 * @typedef {object} VerifyDisclosureBody
 * @property {Record<string, unknown>} reveal - The reveal document to verify.
 * @property {SdCryptosuite} cryptosuite - The cryptosuite it was derived with.
 */

/**
 * Verify a reveal document's derived proof via the genuine verify tool. The
 * verdict is the tool's. Returns 400 if the body is malformed.
 *
 * @param {VerifyDisclosureBody} body - The reveal document and cryptosuite.
 * @returns {Promise<HandlerResult>} The sanitized verdict, or a 400.
 */
export async function postVerifyDisclosure(body) {
  if(!body || typeof body !== 'object' ||
    !body.reveal || typeof body.reveal !== 'object') {
    return {status: 400, body: {error: 'reveal is required and must be an ' +
      'object.'}};
  }
  const result = await verifyDisclosureTool({
    revealDocument: body.reveal,
    cryptosuite: body.cryptosuite
  });
  const {value} = sanitize(result);
  return {status: 200, body: value};
}
