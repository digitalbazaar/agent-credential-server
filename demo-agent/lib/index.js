/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * CLI demo: age-gated access control via VC 2.0 Data Integrity credentials.
 * Provider-agnostic — pick the model with AGENT_PROVIDER or --provider.
 *
 * Usage: `node lib/index.js <scenario> [--provider=NAME]`, where scenario is
 * one of valid, tampered, expired, authn, or sd (selective disclosure).
 */
import * as scenarios from './scenarios.js';
import {buildSdTools} from './sdTools.js';
import {buildTools} from './tools.js';
import {fileURLToPath} from 'node:url';
import {getModel} from './providers.js';
import {runAgent} from './agent.js';

// Load environment variables from the repo-root .env if present. Absent is
// fine — the ollama path needs no key, and real env vars still apply. Resolved
// relative to this file so it works from any working directory.
const REPO_ROOT_ENV = fileURLToPath(new URL('../../.env', import.meta.url));
try {
  process.loadEnvFile(REPO_ROOT_ENV);
} catch {
  // no .env file — rely on the ambient environment
}

process.on('unhandledRejection', reason => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1);
});

const ACTION = 'access:age-restricted-content';

/**
 * Print a progress step to stderr. Kept off stdout so the demo's parsed result
 * lines stay clean, while the user still sees the flow happening during the
 * (sometimes slow) model call.
 *
 * @param {string} message - The progress message.
 * @returns {void}
 */
function step(message) {
  console.error(`… ${message}`);
}

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

/**
 * Run the selective-disclosure demo: the agent asks the wallet to disclose only
 * age_over_21, then verifies the reveal document. The full credential (with the
 * birthdate) never leaves the wallet.
 *
 * @param {string} providerName - The resolved provider name.
 * @param {unknown} model - The AI-SDK model.
 * @returns {Promise<void>}
 */
async function runSdDemo(providerName, model) {
  step('Issuing an SD credential into the holder wallet…');
  const {wallet, agentDid, revealClaims} =
    await scenarios.buildSdAgeDisclosure();

  console.log(`\nScenario: sd  |  Provider: ${providerName}`);
  console.log(`Agent DID: ${agentDid}`);

  const tools = buildSdTools({wallet});
  const prompt =
    'An agent must prove it is over 21 to access age-restricted content, ' +
    'disclosing as little as possible.\n\n' +
    `Agent DID: ${agentDid}\n` +
    `Required claim: ${revealClaims.join(', ')}\n\n` +
    'Ask the wallet (request_disclosure) to reveal only the required ' +
    'claim, then call verify_disclosure on the reveal document and report ' +
    'its verdict.';

  step(`Asking ${providerName} to disclose only ${revealClaims.join(', ')} ` +
    'and verify it (this may take a few seconds)…');
  const result = await runAgent({prompt, model, tools});
  step('Done.');

  const called = result.toolCalls.map(c => c.name).join(', ');
  console.log(`\nTools called: ${called}`);
  console.log(`\nAgent: ${result.finalText}`);
}

async function main() {
  const args = process.argv.slice(2);
  const scenarioName = args.find(a => !a.startsWith('--')) ?? 'valid';
  const {name: providerName, model} = getModel(providerFromArgv(args));

  if(scenarioName === 'sd') {
    await runSdDemo(providerName, model);
    return;
  }

  const build = SCENARIOS[scenarioName];
  if(!build) {
    console.error(
      `Unknown scenario "${scenarioName}". ` +
      `Try: ${Object.keys(SCENARIOS).join(', ')}, sd.`
    );
    process.exit(1);
  }

  step(`Building the "${scenarioName}" scenario (issuing a credential)…`);
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

  step(`Asking ${providerName} to call check_delegation and decide ` +
    '(this may take a few seconds)…');
  const result = await runAgent({prompt, model, tools});
  step('Done.');

  const called = result.toolCalls.map(c => c.name).join(', ');
  console.log(`\nTools called: ${called}`);
  console.log(`Decision: ${result.decision ?? 'NO DECISION'}`);
  console.log(`\nAgent: ${result.finalText}`);
}

main();
