/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Scenario builders for the Cloudflare migration demo: an admin credential, the
 * org root capability, a pre-issued `stage-records` delegation, and a
 * gate-issued single-use `cutover-nameservers` delegation (Model A — the
 * cutover capability exists only after the human signs it at the approval
 * gate). All offline (did:key), using the genuine zcap machinery.
 */
import {
  buildMigrationScenario, STAGE_ACTION, STAGE_TARGET
} from '../cloudflareScenarios.js';
import {verifyDelegationChainTool} from 'mcp-server/lib/tools/verifyChain.js';

describe('buildMigrationScenario', () => {
  it('builds an admin credential bound to the agent with a domain-admin role',
    async () => {
      const s = await buildMigrationScenario();
      expect(s.adminCredential.credentialSubject.id).toBe(s.agentDid);
      expect(s.adminCredential.credentialSubject.role).toBe('domain-admin');
    });

  it('pre-issues a stage delegation that verifies for the stage action',
    async () => {
      const s = await buildMigrationScenario();
      const result = await verifyDelegationChainTool({
        rootCapability: s.rootCapability,
        delegatedCapability: s.stageDelegation,
        agentDid: s.agentDid,
        expectedAction: STAGE_ACTION,
        expectedTarget: STAGE_TARGET
      });
      expect(result.authorized).toBe(true);
    });

  it('does NOT pre-issue a cutover delegation (Model A approval gate)',
    async () => {
      const s = await buildMigrationScenario();
      // the scenario exposes no pre-issued cutover delegation (Model A)
      expect(/** @type {Record<string, unknown>} */ (s).cutoverDelegation)
        .toBeUndefined();
      expect(typeof s.approveCutover).toBe('function');
    });

  it('approveCutover issues a cutover delegation that verifies', async () => {
    const s = await buildMigrationScenario();
    const cutover = await s.approveCutover();
    const result = await verifyDelegationChainTool({
      rootCapability: s.cutoverRootCapability,
      delegatedCapability: cutover,
      agentDid: s.agentDid,
      expectedAction: s.cutoverAction,
      expectedTarget: s.cutoverTarget
    });
    expect(result.authorized).toBe(true);
  });

  it('a stage delegation does not authorize the cutover action (scope)',
    async () => {
      const s = await buildMigrationScenario();
      const result = await verifyDelegationChainTool({
        rootCapability: s.rootCapability,
        delegatedCapability: s.stageDelegation,
        agentDid: s.agentDid,
        expectedAction: s.cutoverAction,
        expectedTarget: s.cutoverTarget
      });
      expect(result.authorized).toBe(false);
    });
});
