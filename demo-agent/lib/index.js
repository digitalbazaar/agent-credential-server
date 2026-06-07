/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * CLI demo: age-gated access control via VC 2.0 Data Integrity credentials.
 * Provider-agnostic — pick the model with AGENT_PROVIDER or --provider.
 *
 * Usage: `node lib/index.js <scenario> [--provider=NAME]`, where scenario is
 * one of valid, tampered, expired, authn, sd (selective disclosure),
 * sd-unlinkable, cloudflare, or dmv (delegated vehicle registration).
 */
import * as scenarios from './scenarios.js';
import {buildCloudflareTools} from './cloudflareTools.js';
import {buildDmvScenario} from './dmvScenarios.js';
import {buildDmvTools} from './dmvTools.js';
import {buildMigrationScenario} from './cloudflareScenarios.js';
import {buildSdTools} from './sdTools.js';
import {buildTools} from './tools.js';
import {createCloudflareServer} from './cloudflare.js';
import {createDmvServer} from './dmv.js';
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
 * Run a selective-disclosure demo: the agent asks the wallet to disclose only
 * age_over_21, then verifies the reveal document. The full credential (with the
 * birthdate) never leaves the wallet. The `unlinkable` variant uses bbs-2023,
 * so the disclosure also cannot be correlated across uses.
 *
 * @param {string} scenarioName - 'sd' or 'sd-unlinkable'.
 * @param {string} providerName - The resolved provider name.
 * @param {unknown} model - The AI-SDK model.
 * @returns {Promise<void>}
 */
async function runSdDemo(scenarioName, providerName, model) {
  const unlinkable = scenarioName === 'sd-unlinkable';
  step(`Issuing a ${unlinkable ? 'bbs-2023 (unlinkable) ' : ''}SD credential ` +
    'into the holder wallet…');
  const {wallet, agentDid, revealClaims} = unlinkable ?
    await scenarios.buildSdUnlinkableDisclosure() :
    await scenarios.buildSdAgeDisclosure();

  console.log(`\nScenario: ${scenarioName}  |  Provider: ${providerName}`);
  console.log(`Agent DID: ${agentDid}  |  Cryptosuite: ${wallet.cryptosuite}`);

  const tools = buildSdTools({wallet});
  const system =
    'You prove an agent meets an age requirement using the least disclosure ' +
    'possible. You do not decide access yourself: request a disclosure from ' +
    'the wallet, then verify it with the verify_disclosure tool and report ' +
    'that tool\'s verdict. Never reveal private keys or hidden claims.';
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
  const result = await runAgent({prompt, model, tools, system});
  step('Done.');

  const called = result.toolCalls.map(c => c.name).join(', ');
  console.log(`\nTools called: ${called}`);
  console.log(`\nAgent: ${result.finalText}`);
}

/**
 * Run the Cloudflare migration demo: the agent verifies the admin credential,
 * stages DNS records, stops for human approval, then cuts over the nameservers
 * using the single-use capability the approval issues. The agent holds no
 * Cloudflare token and cannot cut over before approval.
 *
 * @param {string} providerName - The resolved provider name.
 * @param {unknown} model - The AI-SDK model.
 * @returns {Promise<void>}
 */
async function runCloudflareDemo(providerName, model) {
  step('Issuing the admin credential and scoped delegations…');
  const scenario = await buildMigrationScenario();
  const server = createCloudflareServer();
  const tools = buildCloudflareTools({
    scenario,
    server,
    onToolResult: r => step(
      `tool ${r.name} → ${JSON.stringify(r.output).slice(0, 120)}`
    )
  });

  console.log(`\nScenario: cloudflare  |  Provider: ${providerName}`);
  console.log(`Agent DID: ${scenario.agentDid}`);

  const system =
    'You are an operations agent migrating a website to Cloudflare on behalf ' +
    'of an administrator. You hold no Cloudflare credentials — you act only ' +
    'through the provided tools, each of which enforces its own ' +
    'authorization. Never attempt the irreversible nameserver cutover before ' +
    'obtaining human approval. Report what each tool returns; do not invent ' +
    'outcomes.';
  const prompt =
    'You are migrating a website to Cloudflare on behalf of an ' +
    'administrator. Follow these steps in order, and stop if any step is ' +
    'not authorized:\n' +
    '1. Call verify_admin to confirm the administrator is authorized.\n' +
    '2. Call stage_records to stage the DNS records, then review the diff.\n' +
    '3. The nameserver cutover is irreversible and needs human approval. ' +
    'Call request_cutover_approval to obtain it.\n' +
    '4. Only after approval, call cutover.\n' +
    'Report what happened at each step.';

  step(`Asking ${providerName} to run the migration (this may take a few ` +
    'seconds)…');
  const result = await runAgent({prompt, model, tools, system});
  step('Done.');

  const called = result.toolCalls.map(c => c.name).join(', ');
  console.log(`\nTools called: ${called}`);
  console.log(`\nAgent: ${result.finalText}`);
}

/**
 * Run the CA DMV register-a-vehicle demo: a verified CA driver delegates a
 * scoped, time-boxed register-vehicle capability to the agent. The agent calls
 * register_vehicle, which verifies the driver credential, eligibility claims,
 * the agent auth proof, revocation, and the scoped delegation before recording
 * the (simulated) registration. The agent holds no DMV credentials and cannot
 * register beyond the one delegated action.
 *
 * @param {string} providerName - The resolved provider name.
 * @param {unknown} model - The AI-SDK model.
 * @returns {Promise<void>}
 */
async function runDmvDemo(providerName, model) {
  step('Issuing the driver credential and the scoped delegation…');
  const scenario = await buildDmvScenario({withAuthProof: true});
  const server = await createDmvServer();
  const tools = buildDmvTools({
    scenario,
    server,
    onToolResult: r => step(
      `tool ${r.name} → ${JSON.stringify(r.output).slice(0, 120)}`
    )
  });

  console.log(`\nScenario: dmv  |  Provider: ${providerName}`);
  console.log(`Agent DID: ${scenario.agentDid}`);

  const system =
    'You register a vehicle with the DMV on behalf of a driver. You hold no ' +
    'DMV credentials — you act only through the register_vehicle tool, which ' +
    'enforces its own authorization. You do not decide eligibility yourself: ' +
    'call register_vehicle and report its granted/denied verdict. Never ' +
    'reveal private keys or license PII.';
  const prompt =
    'A verified California driver has delegated to you a scoped capability ' +
    'to register one vehicle on their behalf. Call register_vehicle with the ' +
    'vehicle details, then report the verdict it returns. Do not decide ' +
    'eligibility yourself.\n\n' +
    'Vehicle: 2024 Honda Civic, VIN 1HGEX2024DEMO0001.';

  step(`Asking ${providerName} to register the vehicle (this may take a few ` +
    'seconds)…');
  const result = await runAgent({prompt, model, tools, system});
  step('Done.');

  const called = result.toolCalls.map(c => c.name).join(', ');
  console.log(`\nTools called: ${called}`);
  console.log(`\nAgent: ${result.finalText}`);
}

async function main() {
  const args = process.argv.slice(2);
  const scenarioName = args.find(a => !a.startsWith('--')) ?? 'valid';
  const {name: providerName, model} = getModel(providerFromArgv(args));

  if(scenarioName === 'sd' || scenarioName === 'sd-unlinkable') {
    await runSdDemo(scenarioName, providerName, model);
    return;
  }

  if(scenarioName === 'cloudflare') {
    await runCloudflareDemo(providerName, model);
    return;
  }

  if(scenarioName === 'dmv') {
    await runDmvDemo(providerName, model);
    return;
  }

  const build = SCENARIOS[scenarioName];
  if(!build) {
    const known = `${Object.keys(SCENARIOS).join(', ')}, sd, ` +
      'sd-unlinkable, cloudflare, dmv';
    console.error(`Unknown scenario "${scenarioName}". Try: ${known}.`);
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
