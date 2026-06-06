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
import {buildRootCapability, createZcapDocumentLoader}
  from 'mcp-server/lib/core/zcapChain.js';
import {delegateCapability, makeDelegationController}
  from 'mcp-server/lib/core/zcapDelegate.js';
import {generateKeyPair, toBase64url} from 'mcp-server/lib/core/crypto.js';
import {issueCredentialTool} from 'mcp-server/lib/tools/issue.js';
import {makeDidKeyDriver} from 'mcp-server/lib/tools/didKeyContext.js';

const ZONE = 'sandbox.example';

/** The staging action + its invocation target (DNS records). */
export const STAGE_ACTION = 'stage-records';
export const STAGE_TARGET = `https://cf.internal/zones/${ZONE}/records`;

/** The cutover action + its invocation target (nameservers). */
export const CUTOVER_ACTION = 'cutover-nameservers';
export const CUTOVER_TARGET = `https://cf.internal/zones/${ZONE}/nameservers`;

/**
 * @typedef {import('mcp-server/lib/core/zcapChain.js').RootCapability}
 *   RootCapability
 * @typedef {import('mcp-server/lib/core/zcapDelegate.js').DelegatedZcap}
 *   DelegatedZcap
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
  const driver = makeDidKeyDriver();

  // the org is the root authority and delegator; the agent is the recipient
  const org = await makeDelegationController(driver);
  const agent = await makeDelegationController(driver);

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
  const stageDelegation = await delegateCapability({
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
      return delegateCapability({
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
