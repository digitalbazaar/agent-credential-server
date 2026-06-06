/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Unit tests for the DMV scenario builders and the simulated DMV server. These
 * exercise the building blocks directly (the eval drives them through the
 * agent). Adversarial cases — wrong action, wrong agent, expired, out-of-state,
 * tampered, bad auth proof — outnumber the happy path.
 */
import {buildDmvScenario, REGISTER_ACTION, REGISTER_TARGET}
  from '../dmvScenarios.js';
import {checkDelegation} from 'mcp-server/lib/tools/delegate.js';
import {createDmvServer} from '../dmv.js';
import {jest} from '@jest/globals';
import {verifyDelegationChainTool} from 'mcp-server/lib/tools/verifyChain.js';

// real VC + zcap sign/verify is CPU-heavy; give the suite headroom over the 5s
// default so it stays reliable under parallel CI load
jest.setTimeout(15000);

describe('createDmvServer', () => {
  it('reports a clean credential as not revoked', async () => {
    const server = await createDmvServer();
    const result = await server.checkRevoked(42);
    expect(result.revoked).toBe(false);
  });

  it('reports a revoked credential index as revoked', async () => {
    const server = await createDmvServer({revokedIndexes: [42]});
    const result = await server.checkRevoked(42);
    expect(result.revoked).toBe(true);
    expect(result.reason).toMatch(/revoked/i);
  });

  it('does not revoke a neighbor index', async () => {
    const server = await createDmvServer({revokedIndexes: [42]});
    expect((await server.checkRevoked(41)).revoked).toBe(false);
    expect((await server.checkRevoked(43)).revoked).toBe(false);
  });

  it('records a simulated registration with a confirmation', async () => {
    const server = await createDmvServer();
    const result = server.register({
      make: 'Honda', model: 'Civic', year: 2024, vin: 'VIN123'
    });
    expect(result.registered).toBe(true);
    expect(result.simulated).toBe(true);
    expect(result.confirmation).toMatch(/^CA-REG-\d{6}$/);
  });
});

describe('buildDmvScenario: driver credential', () => {
  it('verifies the credential and required claims for a valid CA driver',
    async () => {
      const scenario = await buildDmvScenario();
      const result = await checkDelegation({
        agentDid: scenario.agentDid,
        requestedAction: REGISTER_ACTION,
        credential: /** @type {any} */ (scenario.driverCredential),
        requiredClaims: /** @type {any} */ (scenario.requiredClaims)
      });
      expect(result.authorized).toBe(true);
    });

  it('omits the license number (data minimization)', async () => {
    const scenario = await buildDmvScenario();
    const subject = scenario.driverCredential.credentialSubject;
    expect(subject.residency).toBe('CA');
    expect(subject.licenseClass).toBe('C');
    expect('licenseNumber' in subject).toBe(false);
  });

  it('denies an out-of-state driver', async () => {
    const scenario = await buildDmvScenario({residency: 'NV'});
    const result = await checkDelegation({
      agentDid: scenario.agentDid,
      requestedAction: REGISTER_ACTION,
      credential: /** @type {any} */ (scenario.driverCredential),
      requiredClaims: /** @type {any} */ (scenario.requiredClaims)
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/residency/i);
  });

  it('denies an expired driver credential', async () => {
    const scenario = await buildDmvScenario({
      credentialExpiresInSeconds: -3600
    });
    const result = await checkDelegation({
      agentDid: scenario.agentDid,
      requestedAction: REGISTER_ACTION,
      credential: /** @type {any} */ (scenario.driverCredential),
      requiredClaims: /** @type {any} */ (scenario.requiredClaims)
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/expire|valid/i);
  });

  it('denies a tampered credential subject', async () => {
    const scenario = await buildDmvScenario({residency: 'NV'});
    // forge CA residency onto a signed NV credential
    const forged = JSON.parse(JSON.stringify(scenario.driverCredential));
    forged.credentialSubject.residency = 'CA';
    const result = await checkDelegation({
      agentDid: scenario.agentDid,
      requestedAction: REGISTER_ACTION,
      credential: forged,
      requiredClaims: /** @type {any} */ (scenario.requiredClaims)
    });
    expect(result.authorized).toBe(false);
  });
});

describe('buildDmvScenario: scoped delegation', () => {
  it('verifies the register-vehicle delegation chain to the agent',
    async () => {
      const scenario = await buildDmvScenario();
      const result = await verifyDelegationChainTool({
        rootCapability: scenario.rootCapability,
        delegatedCapability: scenario.delegation,
        agentDid: scenario.agentDid,
        expectedAction: REGISTER_ACTION,
        expectedTarget: REGISTER_TARGET
      });
      expect(result.authorized).toBe(true);
    });

  it('denies a delegation scoped to a different action', async () => {
    const scenario = await buildDmvScenario({
      delegationAction: 'renew-license'
    });
    const result = await verifyDelegationChainTool({
      rootCapability: scenario.rootCapability,
      delegatedCapability: scenario.delegation,
      agentDid: scenario.agentDid,
      expectedAction: REGISTER_ACTION,
      expectedTarget: REGISTER_TARGET
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/action/i);
  });

  it('denies a delegation issued to a different agent', async () => {
    const otherAgent =
      'did:key:z6MkOtherAgentXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXa';
    const scenario = await buildDmvScenario({delegateToDid: otherAgent});
    const result = await verifyDelegationChainTool({
      rootCapability: scenario.rootCapability,
      delegatedCapability: scenario.delegation,
      agentDid: scenario.agentDid,
      expectedAction: REGISTER_ACTION,
      expectedTarget: REGISTER_TARGET
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/controller|agent/i);
  });
});

describe('buildDmvScenario: agent auth proof', () => {
  it('verifies a fresh, correctly-signed auth proof', async () => {
    const scenario = await buildDmvScenario({withAuthProof: true});
    const result = await checkDelegation({
      agentDid: scenario.agentDid,
      requestedAction: REGISTER_ACTION,
      credential: /** @type {any} */ (scenario.driverCredential),
      requiredClaims: /** @type {any} */ (scenario.requiredClaims),
      authProof: scenario.authProof
    });
    expect(result.authorized).toBe(true);
  });

  it('denies a wrongly-signed auth proof', async () => {
    const scenario = await buildDmvScenario({
      withAuthProof: true, wrongAuthSignature: true
    });
    const result = await checkDelegation({
      agentDid: scenario.agentDid,
      requestedAction: REGISTER_ACTION,
      credential: /** @type {any} */ (scenario.driverCredential),
      requiredClaims: /** @type {any} */ (scenario.requiredClaims),
      authProof: scenario.authProof
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/auth/i);
  });

  it('denies an expired auth challenge', async () => {
    const scenario = await buildDmvScenario({
      withAuthProof: true, expiredChallenge: true
    });
    const result = await checkDelegation({
      agentDid: scenario.agentDid,
      requestedAction: REGISTER_ACTION,
      credential: /** @type {any} */ (scenario.driverCredential),
      requiredClaims: /** @type {any} */ (scenario.requiredClaims),
      authProof: scenario.authProof
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/expire/i);
  });
});
