/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The scenario registry for the web shell: a name -> builder map over the
 * existing demo-agent scenario builders. No business logic of its own — it
 * only selects a builder and labels it; the builders produce real signed
 * credentials and delegations via the genuine mcp-server tools.
 *
 * Each entry's `expected` is the verdict a correct verifier reaches for that
 * scenario, so the UI can show "expected vs actual" and make the adversarial
 * cases self-evidently correct.
 */
import * as scenarios from 'demo-agent/lib/scenarios.js';

/**
 * @typedef {import('demo-agent/lib/scenarios.js').ScenarioInput} ScenarioInput
 */

/**
 * @typedef {object} ScenarioEntry
 * @property {() => Promise<ScenarioInput>} build - The demo-agent builder.
 * @property {'GRANTED' | 'DENIED'} expected - The correct verdict.
 * @property {string} label - A short human label for the UI.
 */

/**
 * The web-exposed L1/L2 scenarios. Adversarial cases outnumber the happy path,
 * mirroring the eval. Keyed by the name used in the URL.
 *
 * @type {Record<string, ScenarioEntry>}
 */
export const SCENARIOS = Object.freeze({
  valid: {
    build: scenarios.buildValid,
    expected: 'GRANTED',
    label: 'Valid credential, required claim met'
  },
  tampered: {
    build: scenarios.buildTampered,
    expected: 'DENIED',
    label: 'Tampered credential (a signed claim was mutated)'
  },
  expired: {
    build: scenarios.buildExpired,
    expected: 'DENIED',
    label: 'Expired credential'
  },
  'not-yet-valid': {
    build: scenarios.buildNotYetValid,
    expected: 'DENIED',
    label: 'Not-yet-valid credential (validFrom in the future)'
  },
  'wrong-agent': {
    build: scenarios.buildWrongAgent,
    expected: 'DENIED',
    label: 'Credential issued to a different agent'
  },
  'missing-claim': {
    build: scenarios.buildMissingClaim,
    expected: 'DENIED',
    label: 'Required claim absent from the credential'
  },
  'wrong-claim-value': {
    build: scenarios.buildWrongClaimValue,
    expected: 'DENIED',
    label: 'Required claim present but with the wrong value'
  },
  authn: {
    build: scenarios.buildAuthnValid,
    expected: 'GRANTED',
    label: 'Valid credential with a signed agent auth proof'
  },
  'authn-wrong-signature': {
    build: scenarios.buildAuthnWrongSignature,
    expected: 'DENIED',
    label: 'Auth proof signed with the wrong key'
  },
  'authn-expired-challenge': {
    build: scenarios.buildAuthnExpiredChallenge,
    expected: 'DENIED',
    label: 'Auth proof over an expired challenge'
  }
});

/**
 * The names of the available scenarios.
 *
 * @returns {string[]} The scenario names.
 */
export function scenarioNames() {
  return Object.keys(SCENARIOS);
}
