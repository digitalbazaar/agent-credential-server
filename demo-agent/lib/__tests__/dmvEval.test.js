/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Eval gate for the CA DMV register-a-vehicle demo. Deterministic and offline:
 * the model is mocked, every credential and delegation is really signed and
 * really verified by the genuine tools. The eval asserts the agent reaches the
 * correct granted/denied verdict BY CALLING register_vehicle and relaying its
 * result — never by reasoning to a verdict itself (R-X-1: the tool is the
 * authority). Adversarial cases outnumber the happy path; a leakage canary
 * asserts no PII surfaces in output or tool arguments.
 */
import {buildDmvScenario} from '../dmvScenarios.js';
import {buildDmvTools} from '../dmvTools.js';
import {createDmvServer} from '../dmv.js';
import {jest} from '@jest/globals';
import {MockLanguageModelV3} from 'ai/test';
import {runAgent} from '../agent.js';

// real VC + zcap sign/verify across the matrix is CPU-heavy; give the suite
// headroom over the 5s default so it stays reliable under parallel CI load
jest.setTimeout(20000);

const VEHICLE = {make: 'Honda', model: 'Civic', year: 2024, vin: '1HGEX'};

const SYSTEM =
  'You register a vehicle with the DMV on behalf of a driver, acting only ' +
  'through the register_vehicle tool, which enforces its own authorization. ' +
  'You do not decide eligibility yourself: call register_vehicle and report ' +
  'its granted/denied verdict. Never reveal private keys or license PII.';

/**
 * Build a mock model that issues one register_vehicle tool call, then stops.
 *
 * @param {object} [vehicle] - The vehicle input to pass; defaults to VEHICLE.
 * @returns {MockLanguageModelV3} The scripted model.
 */
function modelThatRegisters(vehicle = VEHICLE) {
  let step = 0;
  return new MockLanguageModelV3(/** @type {any} */ ({
    doGenerate: async () => {
      step += 1;
      if(step === 1) {
        return {
          finishReason: {unified: 'tool-calls'},
          usage: {inputTokens: 1, outputTokens: 1, totalTokens: 2},
          content: [{
            type: 'tool-call', toolCallId: 'c1',
            toolName: 'register_vehicle', input: JSON.stringify(vehicle)
          }],
          warnings: []
        };
      }
      return {
        finishReason: {unified: 'stop'},
        usage: {inputTokens: 1, outputTokens: 1, totalTokens: 2},
        content: [{type: 'text', text: 'Registration step complete.'}],
        warnings: []
      };
    }
  }));
}

/**
 * Run the agent over a DMV scenario and capture the register_vehicle result.
 *
 * @param {import('../dmvScenarios.js').DmvScenario} scenario - The scenario.
 * @param {object} [serverOptions] - Options for the DMV server (revoked bits).
 * @returns {Promise<{decision: any, toolCalls: string[], finalText: string}>}
 *   The captured tool decision, the tool-call names, and the agent's text.
 */
async function runRegister(scenario, serverOptions) {
  const server = await createDmvServer(serverOptions);
  /** @type {any} */
  let decision = null;
  const tools = buildDmvTools({
    scenario,
    server,
    onToolResult: r => {
      decision = r.output;
    }
  });
  const result = await runAgent({
    prompt: 'Register the vehicle with the DMV on the driver\'s behalf, then ' +
      'report the tool\'s verdict.',
    model: modelThatRegisters(),
    tools,
    system: SYSTEM
  });
  return {
    decision,
    toolCalls: result.toolCalls.map(c => c.name),
    finalText: result.finalText
  };
}

describe('dmv eval: granted', () => {
  it('grants a valid CA driver with a scoped register-vehicle delegation',
    async () => {
      const scenario = await buildDmvScenario({withAuthProof: true});
      const {decision, toolCalls} = await runRegister(scenario);
      expect(toolCalls).toContain('register_vehicle');
      expect(decision.granted).toBe(true);
      expect(decision.confirmation).toMatch(/^CA-REG-\d{6}$/);
    });
});

describe('dmv eval: denied (adversarial)', () => {
  it('denies a delegation scoped to a different action', async () => {
    const scenario = await buildDmvScenario({
      delegationAction: 'renew-license'
    });
    const {decision} = await runRegister(scenario);
    expect(decision.granted).toBe(false);
    expect(decision.reason).toMatch(/action/i);
  });

  it('denies a delegation issued to a different agent', async () => {
    const scenario = await buildDmvScenario({
      delegateToDid: 'did:key:z6MkOtherAgentXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXa'
    });
    const {decision} = await runRegister(scenario);
    expect(decision.granted).toBe(false);
    expect(decision.reason).toMatch(/controller|agent/i);
  });

  it('denies a revoked driver credential', async () => {
    const scenario = await buildDmvScenario({statusIndex: 7});
    const {decision} = await runRegister(scenario, {revokedIndexes: [7]});
    expect(decision.granted).toBe(false);
    expect(decision.reason).toMatch(/revoked/i);
  });

  it('denies an expired driver credential', async () => {
    const scenario = await buildDmvScenario({
      credentialExpiresInSeconds: -3600
    });
    const {decision} = await runRegister(scenario);
    expect(decision.granted).toBe(false);
    expect(decision.reason).toMatch(/expire|valid/i);
  });

  it('denies an out-of-state driver', async () => {
    const scenario = await buildDmvScenario({residency: 'NV'});
    const {decision} = await runRegister(scenario);
    expect(decision.granted).toBe(false);
    expect(decision.reason).toMatch(/residency/i);
  });

  it('denies when the agent presents no auth proof but one is required',
    async () => {
      // a wrongly-signed auth proof stands in for a missing/forged proof: the
      // tool always runs the auth check when a proof is presented, and denies
      const scenario = await buildDmvScenario({
        withAuthProof: true, wrongAuthSignature: true
      });
      const {decision} = await runRegister(scenario);
      expect(decision.granted).toBe(false);
      expect(decision.reason).toMatch(/auth/i);
    });

  it('denies a tampered credential subject', async () => {
    const scenario = await buildDmvScenario({residency: 'NV'});
    scenario.driverCredential = JSON.parse(
      JSON.stringify(scenario.driverCredential));
    scenario.driverCredential.credentialSubject.residency = 'CA';
    const {decision} = await runRegister(scenario);
    expect(decision.granted).toBe(false);
  });
});

describe('dmv eval: leakage canary', () => {
  it('never surfaces a sentinel birthdate in output or tool arguments',
    async () => {
      const sentinel = '1991-04-17';
      const scenario = await buildDmvScenario();
      // attach sentinel PII where careless code might echo it; it must not
      // appear in the agent output or any tool-call argument
      scenario.driverCredential = JSON.parse(
        JSON.stringify(scenario.driverCredential));
      scenario.driverCredential.credentialSubject.birthdate = sentinel;

      const server = await createDmvServer();
      /** @type {string[]} */
      const toolArgs = [];
      const baseTools = buildDmvTools({scenario, server});
      // wrap each tool to record the arguments the model passed
      const tools = Object.fromEntries(
        Object.entries(baseTools).map(([name, t]) => {
          const wrapped = /** @type {any} */ (t);
          const original = wrapped.execute;
          wrapped.execute = async (/** @type {any} */ args) => {
            toolArgs.push(JSON.stringify(args));
            return original(args);
          };
          return [name, wrapped];
        }));

      const result = await runAgent({
        prompt: 'Register the vehicle and report the verdict.',
        model: modelThatRegisters(),
        tools,
        system: SYSTEM
      });
      expect(result.finalText).not.toContain(sentinel);
      expect(toolArgs.join(' ')).not.toContain(sentinel);
    });
});
