/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Demo-agent step de-risk spike.
 *
 * Proves the Vercel AI SDK can (a) drive an in-process tool via
 * generateText({model, tools, stopWhen}) and (b) be mocked deterministically
 * with MockLanguageModelV3 so the eval runs offline with no API key. Scratch
 * artifact, excluded from typecheck/test.
 *
 * Run: `node spikes/ai-sdk-tools.mjs` from the mcp-server workspace.
 * Expected: TOOL CALLED: true / RELAYED RESULT: true.
 *
 * Confirmed versions (pinned in demo-agent/package.json):
 *   ai                     6.0.195
 *   @ai-sdk/anthropic      3.0.81
 *   ollama-ai-provider-v2  3.5.1
 *
 * Findings the eval must carry forward:
 *   1. generateText({model, tools, stopWhen: stepCountIs(n)}) drives in-process
 *      tools (zod inputSchema) end to end; tool results appear in result.steps.
 *   2. In the V3 model interface, doGenerate's `finishReason` is an OBJECT
 *      ({unified: 'tool-calls'}), not the bare string the V2 interface used.
 *   3. Script MockLanguageModelV3 with a FUNCTION-based doGenerate keyed on a
 *      step counter. A bare array of results is not consumed one-per-step as
 *      you might expect, and the tool call silently fails to dispatch.
 */
import {generateText, stepCountIs, tool} from 'ai';
import {MockLanguageModelV3} from 'ai/test';
import {z} from 'zod';

// an in-process tool that records its call (stands in for check_delegation)
let toolCalledWith = null;
const checkDelegation = tool({
  description: 'Decide whether an agent VC authorizes an action.',
  inputSchema: z.object({
    agentDid: z.string(),
    requestedAction: z.string()
  }),
  execute: async input => {
    toolCalledWith = input;
    return {authorized: true, reason: `granted to ${input.agentDid}`};
  }
});

// a mock model scripted by call count: step 1 calls the tool, step 2 emits
// the final text. A function-based doGenerate is reliable; a bare array is not
// consumed one-per-step as you might expect.
let step = 0;
const model = new MockLanguageModelV3({
  doGenerate: async () => {
    step += 1;
    if(step === 1) {
      return {
        finishReason: {unified: 'tool-calls'},
        usage: {inputTokens: 1, outputTokens: 1, totalTokens: 2},
        content: [{
          type: 'tool-call',
          toolCallId: 'c1',
          toolName: 'check_delegation',
          input: JSON.stringify({
            agentDid: 'did:key:zAgent',
            requestedAction: 'access:age-restricted-content'
          })
        }],
        warnings: []
      };
    }
    return {
      finishReason: {unified: 'stop'},
      usage: {inputTokens: 1, outputTokens: 1, totalTokens: 2},
      content: [{
        type: 'text', text: 'ACCESS GRANTED: granted to did:key:zAgent'
      }],
      warnings: []
    };
  }
});

const result = await generateText({
  model,
  tools: {check_delegation: checkDelegation},
  stopWhen: stepCountIs(5),
  prompt: 'Decide access for the agent by calling check_delegation.'
});

console.log('TOOL CALLED:', toolCalledWith !== null);
console.log('tool input:', JSON.stringify(toolCalledWith));
console.log('final text:', result.text);
// the tool result must appear in the steps, and the final text relays it
const toolResults = result.steps.flatMap(s => s.toolResults ?? []);
console.log('tool result:', JSON.stringify(toolResults[0]?.output ?? null));
console.log('RELAYED RESULT:', result.text.includes('GRANTED'));
if(toolCalledWith === null || !result.text.includes('GRANTED')) {
  process.exit(1);
}
