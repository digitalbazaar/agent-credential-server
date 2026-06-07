/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The applied-demo runner for the web shell (Cloudflare migration, CA DMV
 * vehicle registration). It runs the real demo-agent loop over a real scenario
 * and the genuine fail-closed tools, and returns the tool-call trace plus the
 * authoritative tool decision — so the UI can show that the model orchestrates
 * but never decides (KYA-OS R-X-1).
 *
 * By default the model is a deterministic mock that issues the demo's tool
 * sequence (offline, no key, safe for a public site). A live model is used
 * only when WEB_ALLOW_LIVE_MODEL is set and the request opts in — see
 * resolveModel. The mock is intentionally well-behaved; the eval suites cover
 * the misbehaving-model cases.
 */
import {buildCloudflareTools} from 'demo-agent/lib/cloudflareTools.js';
import {buildDmvScenario} from 'demo-agent/lib/dmvScenarios.js';
import {buildDmvTools} from 'demo-agent/lib/dmvTools.js';
import {buildMigrationScenario} from 'demo-agent/lib/cloudflareScenarios.js';
import {createCloudflareServer} from 'demo-agent/lib/cloudflare.js';
import {createDmvServer} from 'demo-agent/lib/dmv.js';
import {MockLanguageModelV3} from 'ai/test';
import {runAgent} from 'demo-agent/lib/agent.js';
import {sanitize} from './sanitize.js';

const STAGE_RECORDS = [
  {type: 'A', name: 'sandbox.example', content: '192.0.2.1'}
];
const VEHICLE = {make: 'Honda', model: 'Civic', year: 2024, vin: '1HGEXDEMO'};

/**
 * @typedef {import('./handlers.js').HandlerResult} HandlerResult
 * @typedef {{toolName: string, input: object}} ScriptedCall
 */

/**
 * @typedef {object} DemoDefinition
 * @property {string} system - The demo's system prompt.
 * @property {string} prompt - The user prompt.
 * @property {ScriptedCall[]} script - The tool sequence the mock model issues.
 * @property {() => Promise<{tools: Record<string, unknown>,
 *   agentDid: string, capture: () => Array<{name: string, output: unknown}>}>}
 *   setup - Build the scenario, server, and tools, with a result capture.
 */

/**
 * Build a deterministic mock model that issues a fixed tool sequence, one call
 * per generate step, then stops. Mirrors the eval's scripted model.
 *
 * @param {ScriptedCall[]} calls - The scripted tool calls.
 * @returns {MockLanguageModelV3} The scripted model.
 */
function scriptedModel(calls) {
  let step = 0;
  return new MockLanguageModelV3(/** @type {any} */ ({
    doGenerate: async () => {
      const call = calls[step];
      step += 1;
      if(call) {
        return {
          finishReason: {unified: 'tool-calls'},
          usage: {inputTokens: 1, outputTokens: 1, totalTokens: 2},
          content: [{
            type: 'tool-call', toolCallId: `c${step}`,
            toolName: call.toolName, input: JSON.stringify(call.input)
          }],
          warnings: []
        };
      }
      return {
        finishReason: {unified: 'stop'},
        usage: {inputTokens: 1, outputTokens: 1, totalTokens: 2},
        content: [{type: 'text', text: 'Demo sequence complete.'}],
        warnings: []
      };
    }
  }));
}

/** @type {Record<string, () => Promise<DemoDefinition>>} */
const DEMOS = {
  async cloudflare() {
    return {
      system:
        'You are an operations agent migrating a website to Cloudflare. You ' +
        'hold no Cloudflare credentials; act only through the tools, each of ' +
        'which enforces its own authorization. Never cut over before human ' +
        'approval. Report what each tool returns.',
      prompt:
        'Migrate the zone: verify the admin, stage records, request approval ' +
        'for the cutover, then cut over only after approval.',
      script: [
        {toolName: 'verify_admin', input: {}},
        {toolName: 'stage_records', input: {records: STAGE_RECORDS}},
        {toolName: 'request_cutover_approval', input: {}},
        {toolName: 'cutover', input: {}}
      ],
      async setup() {
        const scenario = await buildMigrationScenario();
        const server = createCloudflareServer();
        /** @type {Array<{name: string, output: unknown}>} */
        const results = [];
        const tools = buildCloudflareTools({
          scenario, server, onToolResult: r => results.push(r)
        });
        return {tools, agentDid: scenario.agentDid, capture: () => results};
      }
    };
  },
  async dmv() {
    return {
      system:
        'You register a vehicle with the DMV on behalf of a driver. You hold ' +
        'no DMV credentials; act only through register_vehicle, which ' +
        'enforces its own authorization. Report its granted/denied verdict.',
      prompt:
        'Register the vehicle on the driver\'s behalf, then report the ' +
        'verdict the tool returns.',
      script: [{toolName: 'register_vehicle', input: VEHICLE}],
      async setup() {
        const scenario = await buildDmvScenario({withAuthProof: true});
        const server = await createDmvServer();
        /** @type {Array<{name: string, output: unknown}>} */
        const results = [];
        const tools = buildDmvTools({
          scenario, server, onToolResult: r => results.push(r)
        });
        return {tools, agentDid: scenario.agentDid, capture: () => results};
      }
    };
  }
};

/**
 * The names of the available applied demos.
 *
 * @returns {string[]} The demo names.
 */
export function demoNames() {
  return Object.keys(DEMOS);
}

/**
 * Run an applied demo by name with the deterministic mock model, returning the
 * tool-call trace and the authoritative tool decisions. Returns 404 for an
 * unknown name.
 *
 * @param {string} name - The demo name ('cloudflare' | 'dmv').
 * @returns {Promise<HandlerResult>} The sanitized trace + decisions, or a 404.
 */
export async function runDemo(name) {
  const make = DEMOS[name];
  if(!make) {
    return {status: 404, body: {error: `Unknown demo "${name}".`}};
  }
  const demo = await make();
  const {tools, agentDid, capture} = await demo.setup();

  const result = await runAgent({
    prompt: demo.prompt,
    model: scriptedModel(demo.script),
    tools,
    system: demo.system
  });

  const {value} = sanitize({
    name,
    agentDid,
    toolCalls: result.toolCalls.map(c => c.name),
    // the authoritative outcomes the tools produced (not the model's prose)
    decisions: capture(),
    finalText: result.finalText
  });
  return {status: 200, body: value};
}
