/*
 * Copyright (c) 2026 Digital Bazaar, Inc.
 *
 * The Cloudflare migration tool set, exposed to the model as AI-SDK tools. Each
 * tool composes the genuine mcp-server verification tools and the simulated
 * resource server. The agent orchestrates the flow, but the tools are
 * authoritative: a missing or out-of-scope capability denies, and the cutover
 * gate is unbypassable because the agent holds no cutover capability until
 * request_cutover_approval issues one (Model A). See the spec under docs.
 */
import {CUTOVER_ACTION, STAGE_ACTION, STAGE_TARGET}
  from './cloudflareScenarios.js';
import {checkDelegation} from 'mcp-server/lib/tools/delegate.js';
import {tool} from 'ai';
import {verifyDelegationChainTool} from 'mcp-server/lib/tools/verifyChain.js';
import {z} from 'zod';

const REQUIRED_ROLE = {role: {$in: ['domain-admin', 'devops']}};
const MIGRATE_ACTION = 'migrate:cloudflare';

/**
 * @typedef {object} BuildCloudflareToolsOptions
 * @property {import('./cloudflareScenarios.js').MigrationScenario} scenario -
 *   The migration scenario (admin credential + root caps + delegations).
 * @property {import('./cloudflare.js').CloudflareServer} server - The simulated
 *   resource server (staging + single-use cutover store).
 */

/**
 * Build the Cloudflare migration tool set bound to a scenario and server.
 *
 * @param {BuildCloudflareToolsOptions} options - The scenario and server.
 * @returns {Record<string, unknown>} The tool set keyed by tool name.
 */
export function buildCloudflareTools(options) {
  const {scenario, server} = options;

  // Model A: the agent holds no cutover capability until the gate issues one.
  /** @type {(Record<string, unknown> & {id: string}) | null} */
  let cutoverCapability = null;

  return {
    verify_admin: tool({
      description:
        'Verify the administrator credential authorizes a Cloudflare ' +
        'migration (a domain-admin or devops role).',
      inputSchema: z.object({}),
      execute: async () => checkDelegation({
        agentDid: scenario.agentDid,
        requestedAction: MIGRATE_ACTION,
        credential: /** @type {any} */ (scenario.adminCredential),
        requiredClaims: REQUIRED_ROLE
      })
    }),

    stage_records: tool({
      description:
        'Stage DNS records on the zone. Verifies the stage-records ' +
        'capability, then returns a diff of the records it would create. ' +
        'Performs no real change.',
      inputSchema: z.object({
        records: z.array(z.object({
          type: z.string(), name: z.string(), content: z.string()
        }))
      }),
      execute: async ({records}) => {
        const chain = await verifyDelegationChainTool({
          rootCapability: scenario.rootCapability,
          delegatedCapability: scenario.stageDelegation,
          agentDid: scenario.agentDid,
          expectedAction: STAGE_ACTION,
          expectedTarget: STAGE_TARGET
        });
        if(!chain.authorized) {
          return {staged: false, reason: chain.reason};
        }
        return server.stage({zone: 'sandbox.example', records});
      }
    }),

    request_cutover_approval: tool({
      description:
        'Present the staged changes for human approval of the irreversible ' +
        'nameserver cutover. On approval, the human signs a single-use ' +
        'cutover capability (the agent could not cut over before this).',
      inputSchema: z.object({}),
      execute: async () => {
        // the approval gate: the human reviews + signs the cutover capability
        cutoverCapability = await scenario.approveCutover();
        return {approved: true, message: 'Cutover approved by the operator.'};
      }
    }),

    cutover: tool({
      description:
        'Switch the zone nameservers (the irreversible step). Requires an ' +
        'approved single-use cutover capability; denied otherwise.',
      inputSchema: z.object({}),
      execute: async () => {
        // gate: no capability until request_cutover_approval issued one
        if(!cutoverCapability) {
          return {
            authorized: false,
            reason: 'No approved cutover capability; awaiting human approval.'
          };
        }
        const chain = await verifyDelegationChainTool({
          rootCapability: scenario.cutoverRootCapability,
          delegatedCapability: cutoverCapability,
          agentDid: scenario.agentDid,
          expectedAction: CUTOVER_ACTION,
          expectedTarget: scenario.cutoverTarget
        });
        if(!chain.authorized) {
          return {authorized: false, reason: chain.reason};
        }
        // single-use: consume the capability id; a replay is denied
        const consumed = server.recordCutover(cutoverCapability.id);
        if(!consumed.ok) {
          return {authorized: false, reason: consumed.reason};
        }
        return {authorized: true, message: 'Nameservers switched (simulated).'};
      }
    })
  };
}
