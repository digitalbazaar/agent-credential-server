/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Eval gate for the selective-disclosure demo (Phase 2). Deterministic and
 * offline: the model is mocked. The agent obtains a minimal reveal document
 * from the wallet seam and verifies it; the eval asserts the verdict follows
 * the verify tool (R-X-1), the disclosure is minimal (R-L3-1), and the
 * birthdate never reaches the agent's output or tool-call args (R-L3-5).
 */
import * as scenarios from '../scenarios.js';
import {buildSdTools} from '../sdTools.js';
import {MockLanguageModelV3} from 'ai/test';
import {runAgent} from '../agent.js';

/**
 * A mock model that calls request_disclosure then verify_disclosure, then
 * relays the verify verdict. The reveal document flows between steps via the
 * captured tool result, so the model never fabricates it.
 *
 * @param {string[]} revealClaims - The claims to request.
 * @param {{reveal: object | null, valid: boolean | null}} relay - Holder set
 *   from the captured tool results.
 * @returns {MockLanguageModelV3} The scripted model.
 */
function modelThatDisclosesAndVerifies(revealClaims, relay) {
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
            toolName: 'request_disclosure',
            input: JSON.stringify({claims: revealClaims})
          }],
          warnings: []
        };
      }
      if(step === 2) {
        return {
          finishReason: {unified: 'tool-calls'},
          usage: {inputTokens: 1, outputTokens: 1, totalTokens: 2},
          content: [{
            type: 'tool-call', toolCallId: 'c2',
            toolName: 'verify_disclosure',
            input: JSON.stringify({revealDocument: relay.reveal})
          }],
          warnings: []
        };
      }
      const verdict = relay.valid ? 'ACCESS GRANTED' : 'ACCESS DENIED';
      return {
        finishReason: {unified: 'stop'},
        usage: {inputTokens: 1, outputTokens: 1, totalTokens: 2},
        content: [{type: 'text', text: `${verdict}: per verify_disclosure.`}],
        warnings: []
      };
    }
  }));
}

describe('demo-agent SD eval: minimal age disclosure', () => {
  it('grants via a reveal document that discloses only age_over_21',
    async () => {
      const {wallet, revealClaims} = await scenarios.buildSdAgeDisclosure();
      /** @type {{reveal: object | null, valid: boolean | null}} */
      const relay = {reveal: null, valid: null};
      const tools = buildSdTools({
        wallet,
        onDisclosure: reveal => {
          relay.reveal = reveal;
        },
        onVerify: result => {
          relay.valid = result.valid;
        }
      });
      const model = modelThatDisclosesAndVerifies(revealClaims, relay);

      const result = await runAgent({
        prompt: 'Prove the agent is over 21 with minimal disclosure.',
        model, tools
      });

      // verify_disclosure was called and the verdict follows it (R-X-1)
      expect(result.toolCalls.map(c => c.name)).toContain('verify_disclosure');
      expect(relay.valid).toBe(true);
      expect(result.finalText).toContain('GRANTED');

      // disclosure-minimality: the revealed subject has age_over_21 only
      const subject = /** @type {Record<string, unknown>} */ (
        /** @type {any} */ (relay.reveal).credentialSubject
      );
      expect(subject.age_over_21).toBe(true);
      expect(subject.birthdate).toBeUndefined();
      expect(subject.name).toBeUndefined();
    });
});

describe('demo-agent SD eval: leakage canary', () => {
  it('never leaks the birthdate in output or tool args (R-L3-5)', async () => {
    const {scenario, sentinel} =
      await scenarios.buildSdWithSentinelBirthdate();
    /** @type {{reveal: object | null, valid: boolean | null}} */
    const relay = {reveal: null, valid: null};
    const tools = buildSdTools({
      wallet: scenario.wallet,
      onDisclosure: reveal => {
        relay.reveal = reveal;
      },
      onVerify: result => {
        relay.valid = result.valid;
      }
    });
    const model = modelThatDisclosesAndVerifies(scenario.revealClaims, relay);

    const result = await runAgent({
      prompt: 'Prove the agent is over 21 with minimal disclosure.',
      model, tools
    });

    // the birthdate sentinel must not appear in the agent's final answer...
    expect(result.finalText).not.toContain(sentinel);
    // ...nor in any argument the agent passed to any tool
    const allArgs = JSON.stringify(result.toolCalls.map(c => c.input));
    expect(allArgs).not.toContain(sentinel);
  });
});
