/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * IO boundary for delegation-chain verification, built on @digitalbazaar/zcap.
 * A delegated capability embeds its parent and references the root by id, so
 * verifying the leaf delegation against the expected root walks the whole
 * chain cryptographically.
 */
import {checkLeafController, createZcapDocumentLoader}
  from '../core/zcapChain.js';
import {CapabilityDelegation} from '@digitalbazaar/zcap';
import {cryptosuite as eddsaRdfc2022}
  from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {makeDidKeyDriver} from './didKeyContext.js';
import jsigs from 'jsonld-signatures';

/**
 * @typedef {import('../core/zcapChain.js').RootCapability} RootCapability
 */

/**
 * @typedef {object} VerifyChainInput
 * @property {RootCapability} rootCapability - The root capability the chain
 *   must descend from.
 * @property {Record<string, unknown> & {controller?: string}}
 *   delegatedCapability - The leaf delegated capability presented by the agent
 *   (it embeds its parent chain).
 * @property {string} agentDid - The DID that must control the leaf capability.
 * @property {string} expectedAction - The action the chain must allow.
 * @property {string} expectedTarget - The invocation target the chain covers.
 */

/**
 * @typedef {object} VerifyChainResult
 * @property {boolean} authorized
 * @property {string} reason
 */

/**
 * Verify a delegation chain from a root capability down to an agent.
 *
 * @param {VerifyChainInput} input - Root, leaf capability, agent, action,
 *   target.
 * @returns {Promise<VerifyChainResult>} Whether the chain authorizes the agent.
 */
export async function verifyDelegationChainTool(input) {
  const {
    rootCapability, delegatedCapability, agentDid, expectedAction,
    expectedTarget
  } = input;

  // 1. The leaf must be delegated to the expected agent (zcap verifies chain
  //    continuity but not the specific recipient DID).
  const leafCheck = checkLeafController({
    capability: delegatedCapability,
    expectedController: agentDid
  });
  if(!leafCheck.valid) {
    return {authorized: false, reason: leafCheck.reason ?? 'Wrong leaf agent'};
  }

  // 2. Verify the delegation chain: proofs, continuity, expiry attenuation,
  //    and that it descends from the expected root.
  const documentLoader = createZcapDocumentLoader({
    didKeyDriver: makeDidKeyDriver(),
    rootCapabilities: [rootCapability]
  });
  let result;
  try {
    result = await jsigs.verify(delegatedCapability, {
      documentLoader,
      suite: new DataIntegrityProof({cryptosuite: eddsaRdfc2022}),
      purpose: new CapabilityDelegation({
        suite: new DataIntegrityProof({cryptosuite: eddsaRdfc2022}),
        expectedRootCapability: rootCapability.id,
        expectedTarget,
        expectedAction
      })
    });
  } catch(e) {
    const message = e instanceof Error ? e.message : String(e);
    return {authorized: false, reason: `Chain verification threw: ${message}`};
  }

  if(!result.verified) {
    const error = result.error?.errors?.[0]?.message ??
      result.error?.message ?? 'Delegation chain verification failed';
    return {authorized: false, reason: error};
  }

  return {
    authorized: true,
    reason: `Delegation chain verified for agent ${agentDid}`
  };
}
