/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * CLI demo: age-gated access control via VC 2.0 Data Integrity credentials.
 * Provider-agnostic — pick the model with AGENT_PROVIDER or --provider.
 *
 * Usage:
 *   node lib/index.js valid                  → valid VC, access granted
 *   node lib/index.js tampered               → tampered VC, access denied
 *   node lib/index.js expired                → expired VC, access denied
 *   node lib/index.js authn                  → challenge-response + delegation
 *   node lib/index.js valid --provider=ollama
 */
import {buildTools} from './tools.js';
import {getModel} from './providers.js';
import {runAgent} from './agent.js';
import * as scenarios from './scenarios.js';

process.on('unhandledRejection', reason => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1);
});

const ACTION = 'access:age-restricted-content';

/**
 * @type {Record<string,
 *   () => Promise<import('./scenarios.js').ScenarioInput>>}
 */
const SCENARIOS = {
  valid: scenarios.buildValid,
  tampered: scenarios.buildTampered,
  expired: scenarios.buildExpired,
  authn: scenarios.buildAuthnValid
};

/**
 * Parse a --provider=NAME flag from argv, if present.
 *
 * @param {string[]} argv - The process arguments.
 * @returns {string | undefined} The provider name, or undefined.
 */
function providerFromArgv(argv) {
  const flag = argv.find(a => a.startsWith('--provider='));
  return flag ? flag.slice('--provider='.length) : undefined;
}

async function main() {
  const args = process.argv.slice(2);
  const scenarioName = args.find(a => !a.startsWith('--')) ?? 'valid';
  const build = SCENARIOS[scenarioName];
  if(!build) {
    console.error(
      `Unknown scenario "${scenarioName}". ` +
      `Try: ${Object.keys(SCENARIOS).join(', ')}.`
    );
    process.exit(1);
  }

  const {name: providerName, model} = getModel(providerFromArgv(args));
  /** @type {import('./scenarios.js').ScenarioInput} */
  const input = await build();
  const tools = buildTools({});

  console.log(`\nScenario: ${scenarioName}  |  Provider: ${providerName}`);
  console.log(`Agent DID: ${input.agentDid}`);

  const prompt =
    'An agent requests access to age-restricted content. Decide whether to ' +
    'allow it.\n\n' +
    `Agent DID: ${input.agentDid}\n` +
    `Requested action: ${ACTION}\n` +
    `Credential: ${JSON.stringify(input.credential)}\n` +
    (input.requiredClaims ?
      `Required claims: ${JSON.stringify(input.requiredClaims)}\n` : '') +
    (input.authProof ?
      `Agent auth proof: ${JSON.stringify(input.authProof)}\n` : '') +
    '\nCall check_delegation to decide, then report its verdict.';

  const result = await runAgent({prompt, model, tools});

  console.log(`\nTools called: ${result.toolCalls.map(c => c.name).join(', ')}`);
  console.log(`Decision: ${result.decision ?? 'NO DECISION'}`);
  console.log(`\nAgent: ${result.finalText}`);
}

main();
