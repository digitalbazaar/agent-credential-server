/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/*
 * Scenario builders for the Cloudflare migration demo: an admin credential,
 * the org root capability, and two scoped zcap delegations.
 *
 * The Model-A approval gate means the cutover capability is NOT pre-issued.
 * It exists only after approveCutover() is called, i.e. after the simulated
 * human reviews the staged diff and signs it. The agent cannot cut over until
 * then. The full design is in docs/cloudflare-migration-spec.md.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {buildRootCapability, createZcapDocumentLoader}
  from 'mcp-server/lib/core/zcapChain.js';
import {generateKeyPair, toBase64url} from 'mcp-server/lib/core/crypto.js';
import {CapabilityDelegation} from '@digitalbazaar/zcap';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';
import {cryptosuite as eddsaRdfc2022}
  from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import {issueCredentialTool} from 'mcp-server/lib/tools/issue.js';
import jsigs from 'jsonld-signatures';

const ZONE = 'sandbox.example';

/** The staging action + its invocation target (DNS records). */
export const STAGE_ACTION = 'stage-records';
export const STAGE_TARGET = `https://cf.internal/zones/${ZONE}/records`;

/** The cutover action + its invocation target (nameservers). */
export const CUTOVER_ACTION = 'cutover-nameservers';
export const CUTOVER_TARGET = `https://cf.internal/zones/${ZONE}/nameservers`;

/**
 * Build a did:key controller with a capabilityDelegation signer.
 *
 * @param {import('@digitalbazaar/did-method-key').DidKeyDriver} driver - The
 *   did:key driver.
 * @returns {Promise<{did: string, signer: object}>} The controller.
 */
async function makeController(driver) {
  const keyPair = await Ed25519Multikey.generate();
  const {didDocument, methodFor} = await driver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const vm = methodFor({purpose: 'capabilityDelegation'});
  keyPair.id = vm.id;
  keyPair.controller = didDocument.id;
  return {did: didDocument.id, signer: keyPair.signer()};
}

/**
 * Sign a delegated capability from a parent to a controller, scoped to one
 * action and target.
 *
 * @param {object} input - Delegation parameters.
 * @param {{id: string}} input.parent - The parent capability.
 * @param {object} input.signer - The delegator's signer.
 * @param {string} input.toController - The recipient (agent) DID.
 * @param {string} input.action - The single allowed action.
 * @param {string} input.target - The invocation target.
 * @param {number} input.expiresInSeconds - Lifetime from now.
 * @param {(url: string) => Promise<unknown>} input.loader - The zcap document
 *   loader.
 * @returns {Promise<Record<string, unknown> & {id: string}>} The signed zcap.
 */
async function delegate(input) {
  const {
    parent, signer, toController, action, target, expiresInSeconds, loader
  } = input;
  const zcap = {
    '@context': ['https://w3id.org/zcap/v1'],
    id: `urn:uuid:${crypto.randomUUID()}`,
    parentCapability: parent.id,
    invocationTarget: target,
    controller: toController,
    allowedAction: action,
    expires: new Date(Date.now() + expiresInSeconds * 1000).toISOString()
  };
  const signed = await jsigs.sign(zcap, {
    documentLoader: loader,
    suite: new DataIntegrityProof({signer, cryptosuite: eddsaRdfc2022}),
    purpose: new CapabilityDelegation({parentCapability: parent})
  });
  return /** @type {Record<string, unknown> & {id: string}} */ (signed);
}

/**
 * @typedef {import('mcp-server/lib/core/zcapChain.js').RootCapability}
 *   RootCapability
 * @typedef {Record<string, unknown> & {id: string,
 *   controller?: string, allowedAction?: string | string[]}} DelegatedZcap
 */

/**
 * @typedef {object} MigrationScenario
 * @property {string} agentDid - The agent the capabilities are delegated to.
 * @property {import('mcp-server/lib/core/vc.js').DataIntegrityCredential}
 *   adminCredential - The admin VC (credentialSubject carries the role claim).
 * @property {RootCapability} rootCapability - The org root capability over the
 *   stage-records resource.
 * @property {RootCapability} cutoverRootCapability - The org root capability
 *   over the nameserver-cutover resource.
 * @property {DelegatedZcap} stageDelegation - The pre-issued stage-records
 *   delegation.
 * @property {string} cutoverAction - CUTOVER_ACTION (convenience).
 * @property {string} cutoverTarget - CUTOVER_TARGET (convenience).
 * @property {() => Promise<DelegatedZcap>} approveCutover - The approval gate:
 *   issue the single-use cutover delegation (Model A). Only the org signer
 *   can produce it.
 */

/**
 * Build the Cloudflare migration scenario. The admin credential + the stage
 * delegation are issued up front; the cutover delegation is withheld behind
 * `approveCutover` (the human approval gate).
 *
 * @param {object} [options] - Scenario options.
 * @param {string} [options.role] - The admin role to assert; override for
 *   adversarial cases such as a non-admin.
 * @returns {Promise<MigrationScenario>} The scenario.
 */
export async function buildMigrationScenario(options = {}) {
  const role = options.role ?? 'domain-admin';
  const driver = didKeyDriverFactory();
  driver.use({
    multibaseMultikeyHeader: 'z6Mk',
    fromMultibase: Ed25519Multikey.from
  });

  // the org is the root authority and delegator; the agent is the recipient
  const org = await makeController(driver);
  const agent = await makeController(driver);

  // root capabilities over the two protected resources (stage + cutover)
  const stageRoot = buildRootCapability({
    controller: org.did, invocationTarget: STAGE_TARGET
  });
  const cutoverRoot = buildRootCapability({
    controller: org.did, invocationTarget: CUTOVER_TARGET
  });
  const loader = createZcapDocumentLoader({
    didKeyDriver: driver, rootCapabilities: [stageRoot, cutoverRoot]
  });

  // admin VC: the org asserts the admin role (issuer did:key from the key)
  const orgKp = await generateKeyPair();
  const adminCredential = await issueCredentialTool({
    subjectDid: agent.did,
    claims: {role, scopes: ['dns:manage', 'zone:create']},
    privateKeyBase64url: toBase64url(orgKp.privateKey),
    expiresInSeconds: 3600
  });

  // pre-issue the stage delegation (org -> agent), scoped to stage-records
  const stageDelegation = await delegate({
    parent: stageRoot,
    signer: org.signer,
    toController: agent.did,
    action: STAGE_ACTION,
    target: STAGE_TARGET,
    expiresInSeconds: 1800,
    loader
  });

  return {
    agentDid: agent.did,
    adminCredential,
    rootCapability: stageRoot,
    cutoverRootCapability: cutoverRoot,
    stageDelegation,
    cutoverAction: CUTOVER_ACTION,
    cutoverTarget: CUTOVER_TARGET,
    // Model A: the cutover capability is created only when the human approves.
    async approveCutover() {
      return delegate({
        parent: cutoverRoot,
        signer: org.signer,
        toController: agent.did,
        action: CUTOVER_ACTION,
        target: CUTOVER_TARGET,
        expiresInSeconds: 600,
        loader
      });
    }
  };
}
