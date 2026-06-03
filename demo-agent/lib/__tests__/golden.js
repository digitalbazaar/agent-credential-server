/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Golden dataset for the demo-agent eval gate.
 *
 * Each case describes a credential/action scenario, the decision the
 * authorization tool (check_delegation) returns for it, and whether the agent
 * MUST call that tool. The eval asserts the agent reaches the expected decision
 * BY CALLING THE TOOL and faithfully relaying its result — never by reasoning
 * to a verdict on its own. The tool's decision correctness itself is covered by
 * the pure delegate.test.js in mcp-server.
 *
 * Cases are pure data plus a `buildInputs` that produces the real
 * check_delegation input (a signed VC 2.0 credential and the agent DID) via the
 * mcp-server tools, so the mocked tool call runs the genuine handler.
 */

/**
 * @typedef {object} GoldenCase
 * @property {string} name - A short scenario label.
 * @property {() => Promise<object>} buildInputs - Builds the check_delegation
 *   input for this scenario (async; issues a real DI credential).
 * @property {'GRANTED' | 'DENIED'} expectedDecision - The expected verdict.
 * @property {boolean} mustCallTool - Whether the agent must call the
 *   authorization tool to reach the verdict (always true here).
 */

/**
 * The labeled scenarios. `buildInputs` is supplied by the test, which has
 * access to the scenario builders; this module defines the matrix and labels.
 *
 * @param {any} scenarios - The scenario builder module (injected by the test;
 *   its `build*` functions land with scenarios.js in a later commit).
 * @returns {GoldenCase[]} The golden cases.
 */
export function goldenCases(scenarios) {
  return [
    {
      name: 'valid credential, all claims satisfied',
      buildInputs: () => scenarios.buildValid(),
      expectedDecision: 'GRANTED',
      mustCallTool: true
    },
    {
      name: 'valid credential, no required claims',
      buildInputs: () => scenarios.buildValidNoClaims(),
      expectedDecision: 'GRANTED',
      mustCallTool: true
    },
    {
      name: 'expired credential',
      buildInputs: () => scenarios.buildExpired(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'tampered credentialSubject',
      buildInputs: () => scenarios.buildTampered(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'wrong agent presents someone else\'s credential',
      buildInputs: () => scenarios.buildWrongAgent(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'required claim missing',
      buildInputs: () => scenarios.buildMissingClaim(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'required claim has the wrong value',
      buildInputs: () => scenarios.buildWrongClaimValue(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'predicate $gte satisfied (age >= 21)',
      buildInputs: () => scenarios.buildPredicateGtePass(),
      expectedDecision: 'GRANTED',
      mustCallTool: true
    },
    {
      name: 'predicate $gte not satisfied (age < 21)',
      buildInputs: () => scenarios.buildPredicateGteFail(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'predicate $in satisfied (role in set)',
      buildInputs: () => scenarios.buildPredicateInPass(),
      expectedDecision: 'GRANTED',
      mustCallTool: true
    },
    {
      name: 'predicate $in not satisfied (role not in set)',
      buildInputs: () => scenarios.buildPredicateInFail(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'licensed professional, role and license satisfied',
      buildInputs: () => scenarios.buildLicensedProfessionalPass(),
      expectedDecision: 'GRANTED',
      mustCallTool: true
    },
    {
      name: 'professional role matches but license is false',
      buildInputs: () => scenarios.buildLicensedProfessionalFail(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'membership tier meets numeric threshold (non-age $gte)',
      buildInputs: () => scenarios.buildMembershipTierPass(),
      expectedDecision: 'GRANTED',
      mustCallTool: true
    },
    {
      name: 'membership tier below numeric threshold',
      buildInputs: () => scenarios.buildMembershipTierFail(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'not-yet-valid credential (validFrom in the future)',
      buildInputs: () => scenarios.buildNotYetValid(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'authn: valid credential and valid auth proof',
      buildInputs: () => scenarios.buildAuthnValid(),
      expectedDecision: 'GRANTED',
      mustCallTool: true
    },
    {
      name: 'authn: wrong auth-proof signature',
      buildInputs: () => scenarios.buildAuthnWrongSignature(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    },
    {
      name: 'authn: expired challenge',
      buildInputs: () => scenarios.buildAuthnExpiredChallenge(),
      expectedDecision: 'DENIED',
      mustCallTool: true
    }
  ];
}
