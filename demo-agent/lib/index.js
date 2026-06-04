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
import {getModel} from './providers.js';
import {runAgent} from './agent.js';

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

  const result = await runAgent({prompt, model, tools});
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

  const called = result.toolCalls.map(c => c.name).join(', ');
  console.log(`\nTools called: ${called}`);
  console.log(`Decision: ${result.decision ?? 'NO DECISION'}`);
  console.log(`\nAgent: ${result.finalText}`);
}

main();
