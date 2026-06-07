/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Request handlers for the web shell. Each is a thin adapter: it selects a
 * scenario builder or calls an existing mcp-server tool, then sanitizes the
 * result before it can cross to the browser. The handlers hold no crypto/VC
 * logic — that all lives in the already-tested mcp-server core — and they are
 * framework-agnostic (no Fastify types), so they unit-test without HTTP.
 *
 * KYA-OS R-X-1: the verdict comes from checkDelegation (tested pure code), not
 * from the client. R-X-2: every response passes through sanitize(), so no key
 * material or signer escapes.
 */
import {checkDelegation} from 'mcp-server/lib/tools/delegate.js';
import {sanitize} from './sanitize.js';
import {SCENARIOS} from './scenarios.js';

/**
 * @typedef {object} HandlerResult
 * @property {number} status - The HTTP status code.
 * @property {unknown} body - The JSON body (already sanitized).
 */

/**
 * Build a scenario by name: a real signed credential + DIDs + required claims,
 * with the issuer/agent keys stripped. Returns 404 for an unknown name.
 *
 * @param {string} name - The scenario name (see SCENARIOS).
 * @returns {Promise<HandlerResult>} The sanitized scenario, or a 404.
 */
export async function getScenario(name) {
  const entry = SCENARIOS[name];
  if(!entry) {
    return {
      status: 404,
      body: {error: `Unknown scenario "${name}".`}
    };
  }
  const input = await entry.build();
  const {value} = sanitize(input);
  return {
    status: 200,
    body: {
      name,
      label: entry.label,
      expected: entry.expected,
      scenario: value
    }
  };
}

/**
 * @typedef {object} CheckDelegationBody
 * @property {string} agentDid - The requesting agent DID.
 * @property {string} requestedAction - The action being requested.
 * @property {object} credential - The VC 2.0 credential to verify.
 * @property {Record<string, unknown>} [requiredClaims] - Required claims.
 * @property {object} [authProof] - Optional agent auth proof.
 */

/**
 * Verify a credential against a requested action via the genuine
 * checkDelegation tool, returning its structured verdict. The verdict is the
 * tool's, never the client's. Returns 400 if the required fields are missing.
 *
 * @param {CheckDelegationBody} body - The request body.
 * @returns {Promise<HandlerResult>} The sanitized verdict, or a 400.
 */
export async function postCheckDelegation(body) {
  const problem = validateCheckDelegation(body);
  if(problem) {
    return {status: 400, body: {error: problem}};
  }
  const result = await checkDelegation({
    agentDid: body.agentDid,
    requestedAction: body.requestedAction,
    credential: /** @type {any} */ (body.credential),
    requiredClaims: /** @type {any} */ (body.requiredClaims ?? {}),
    authProof: /** @type {any} */ (body.authProof)
  });
  const {value} = sanitize(result);
  return {status: 200, body: value};
}

/**
 * Validate the check-delegation request body server-side (the client is never
 * authoritative). Returns an error message, or null if the body is well-formed.
 *
 * @param {Partial<CheckDelegationBody>} body - The request body to validate.
 * @returns {string | null} An error message, or null if valid.
 */
export function validateCheckDelegation(body) {
  if(!body || typeof body !== 'object') {
    return 'Request body must be a JSON object.';
  }
  if(typeof body.agentDid !== 'string' || body.agentDid.length === 0) {
    return 'agentDid is required and must be a string.';
  }
  if(typeof body.requestedAction !== 'string') {
    return 'requestedAction is required and must be a string.';
  }
  if(!body.credential || typeof body.credential !== 'object') {
    return 'credential is required and must be an object.';
  }
  return null;
}
