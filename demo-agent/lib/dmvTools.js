/*
 * Copyright (c) 2026 Digital Bazaar, Inc.
 *
 * The CA DMV register-a-vehicle tool set, exposed to the model as AI-SDK tools.
 * The single register_vehicle tool composes the genuine mcp-server verification
 * tools and the simulated DMV server in a numbered, fail-closed pipeline: it
 * verifies the driver credential and required claims (and the agent auth proof
 * if present), checks revocation against the DMV status list, verifies the
 * scoped register-vehicle delegation chain, and only then performs the
 * simulated registration. The tool is authoritative — the agent reaches no
 * verdict itself. See the spec under docs.
 */
import {REGISTER_ACTION, REGISTER_TARGET} from './dmvScenarios.js';
import {checkDelegation} from 'mcp-server/lib/tools/delegate.js';
import {tool} from 'ai';
import {verifyDelegationChainTool} from 'mcp-server/lib/tools/verifyChain.js';
import {z} from 'zod';

/**
 * @typedef {object} BuildDmvToolsOptions
 * @property {import('./dmvScenarios.js').DmvScenario} scenario - The DMV
 *   scenario (driver credential + root capability + scoped delegation).
 * @property {import('./dmv.js').DmvServer} server - The simulated DMV server
 *   (status list + registration store).
 * @property {(record: {name: string, output: unknown}) => void} [onToolResult]
 *   - Observer invoked with each tool's result (used by the eval to capture the
 *   authoritative outcomes).
 */

/**
 * @typedef {object} RegisterDecision
 * @property {boolean} granted - Whether the registration was authorized.
 * @property {string} reason - Why it was granted or denied.
 * @property {string} [confirmation] - The confirmation number, when granted.
 */

/**
 * Build the DMV register-a-vehicle tool set bound to a scenario and server.
 *
 * @param {BuildDmvToolsOptions} options - The scenario and server.
 * @returns {Record<string, unknown>} The tool set keyed by tool name.
 */
export function buildDmvTools(options) {
  const {scenario, server, onToolResult} = options;

  /**
   * Report a tool result to the observer (if any) and return it unchanged.
   *
   * @param {RegisterDecision} output - The decision.
   * @returns {RegisterDecision} The same decision.
   */
  function record(output) {
    if(onToolResult) {
      onToolResult({name: 'register_vehicle', output});
    }
    return output;
  }

  return {
    register_vehicle: tool({
      description:
        'Register a vehicle with the CA DMV on the driver\'s behalf. ' +
        'Verifies the driver credential, the required eligibility claims, ' +
        'revocation, and the scoped register-vehicle delegation before ' +
        'recording the (simulated) registration. Returns a granted/denied ' +
        'decision.',
      inputSchema: z.object({
        make: z.string(),
        model: z.string(),
        year: z.number(),
        vin: z.string()
      }),
      execute: async vehicle => {
        // 1. Verify the driver credential: proof, issuer, validity window, the
        //    required claims, and the agent auth proof if one is presented.
        const delegation = await checkDelegation({
          agentDid: scenario.agentDid,
          requestedAction: REGISTER_ACTION,
          credential: /** @type {any} */ (scenario.driverCredential),
          requiredClaims: /** @type {any} */ (scenario.requiredClaims),
          authProof: scenario.authProof
        });
        if(!delegation.authorized) {
          return record({granted: false, reason: delegation.reason});
        }

        // 2. Check revocation against the DMV status list (in memory, no
        //    network) — a revoked driver credential is denied.
        const revocation = await server.checkRevoked(scenario.statusIndex);
        if(revocation.revoked) {
          return record({
            granted: false,
            reason: revocation.reason ?? 'Driver credential revoked'
          });
        }

        // 3. Verify the scoped register-vehicle delegation chain from the DMV
        //    root down to this agent (action + target must match).
        const chain = await verifyDelegationChainTool({
          rootCapability: scenario.rootCapability,
          delegatedCapability: scenario.delegation,
          agentDid: scenario.agentDid,
          expectedAction: REGISTER_ACTION,
          expectedTarget: REGISTER_TARGET
        });
        if(!chain.authorized) {
          return record({granted: false, reason: chain.reason});
        }

        // 4. All checks passed — perform the simulated registration.
        const result = server.register(vehicle);
        return record({
          granted: true,
          reason: `Vehicle registered for agent ${scenario.agentDid}.`,
          confirmation: result.confirmation
        });
      }
    })
  };
}
