/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Unit tests for the demo scenario builders. These run the genuine
 * check_delegation handler against each built input and assert the decision
 * matches the scenario's intent — confirming the scenarios are well-formed and
 * the golden labels are correct, independent of any LLM.
 */
import * as scenarios from '../scenarios.js';
import {checkDelegation} from 'mcp-server/lib/tools/delegate.js';

const ACTION = 'access:age-restricted-content';

/**
 * Decide a scenario by running the real check_delegation handler.
 *
 * @param {any} input - The scenario input.
 * @returns {Promise<boolean>} Whether the action was authorized.
 */
async function decide(input) {
  // drop the test-only sentinel before calling the real handler
  const rest = {...input};
  delete rest._sentinel;
  const result = await checkDelegation({...rest, requestedAction: ACTION});
  return result.authorized;
}

describe('scenarios decide as labeled', () => {
  it('valid → authorized', async () => {
    expect(await decide(await scenarios.buildValid())).toBe(true);
  });
  it('valid no-claims → authorized', async () => {
    expect(await decide(await scenarios.buildValidNoClaims())).toBe(true);
  });
  it('expired → denied', async () => {
    expect(await decide(await scenarios.buildExpired())).toBe(false);
  });
  it('tampered → denied', async () => {
    expect(await decide(await scenarios.buildTampered())).toBe(false);
  });
  it('wrong agent → denied', async () => {
    expect(await decide(await scenarios.buildWrongAgent())).toBe(false);
  });
  it('missing claim → denied', async () => {
    expect(await decide(await scenarios.buildMissingClaim())).toBe(false);
  });
  it('wrong claim value → denied', async () => {
    expect(await decide(await scenarios.buildWrongClaimValue())).toBe(false);
  });
  it('predicate $gte pass → authorized', async () => {
    expect(await decide(await scenarios.buildPredicateGtePass())).toBe(true);
  });
  it('predicate $gte fail → denied', async () => {
    expect(await decide(await scenarios.buildPredicateGteFail())).toBe(false);
  });
  it('predicate $in pass → authorized', async () => {
    expect(await decide(await scenarios.buildPredicateInPass())).toBe(true);
  });
  it('predicate $in fail → denied', async () => {
    expect(await decide(await scenarios.buildPredicateInFail())).toBe(false);
  });
  it('authn valid → authorized', async () => {
    expect(await decide(await scenarios.buildAuthnValid())).toBe(true);
  });
  it('authn wrong signature → denied', async () => {
    const input = await scenarios.buildAuthnWrongSignature();
    expect(await decide(input)).toBe(false);
  });
  it('authn expired challenge → denied', async () => {
    expect(await decide(await scenarios.buildAuthnExpiredChallenge()))
      .toBe(false);
  });
});

describe('buildWithSentinelSecret', () => {
  it('returns a sentinel and a still-valid scenario', async () => {
    const {input, sentinel} = await scenarios.buildWithSentinelSecret();
    expect(sentinel).toMatch(/^CANARY-SECRET-/);
    expect(await decide(input)).toBe(true);
  });
});
