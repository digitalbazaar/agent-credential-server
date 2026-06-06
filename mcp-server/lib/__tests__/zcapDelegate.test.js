/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The shared zcap-delegation signing helpers: make an Ed25519 did:key
 * controller and sign a scoped delegated capability. These compose with the
 * verify-side zcapChain helpers (buildRootCapability and the chain verifier)
 * and were previously duplicated in verifyChain.test.js and the demo scenario
 * builders.
 */
import {
  buildRootCapability, createZcapDocumentLoader
} from '../core/zcapChain.js';
import {delegateCapability, makeDelegationController}
  from '../core/zcapDelegate.js';
import {makeDidKeyDriver} from '../tools/didKeyContext.js';
import {verifyDelegationChainTool} from '../tools/verifyChain.js';

const TARGET = 'https://resource.example/thing';
const ACTION = 'do-thing';

describe('makeDelegationController', () => {
  it('produces a did:key controller with a capabilityDelegation signer',
    async () => {
      const driver = makeDidKeyDriver();
      const ctrl = await makeDelegationController(driver);
      expect(ctrl.did).toMatch(/^did:key:z6Mk/);
      expect(ctrl.signer).toBeDefined();
      expect(typeof ctrl.signer).toBe('object');
    });
});

describe('delegateCapability', () => {
  it('signs a delegation that verifies for its action and target',
    async () => {
      const driver = makeDidKeyDriver();
      const alice = await makeDelegationController(driver);
      const agent = await makeDelegationController(driver);
      const root = buildRootCapability({
        controller: alice.did, invocationTarget: TARGET
      });
      const loader = createZcapDocumentLoader({
        didKeyDriver: driver, rootCapabilities: [root]
      });
      const zcap = await delegateCapability({
        parent: root,
        signer: alice.signer,
        toController: agent.did,
        action: ACTION,
        target: TARGET,
        expiresInSeconds: 600,
        loader
      });
      expect(zcap.id).toMatch(/^urn:uuid:/);
      const result = await verifyDelegationChainTool({
        rootCapability: root,
        delegatedCapability: zcap,
        agentDid: agent.did,
        expectedAction: ACTION,
        expectedTarget: TARGET
      });
      expect(result.authorized).toBe(true);
    });

  it('signs a delegation that fails verification for a different action',
    async () => {
      const driver = makeDidKeyDriver();
      const alice = await makeDelegationController(driver);
      const agent = await makeDelegationController(driver);
      const root = buildRootCapability({
        controller: alice.did, invocationTarget: TARGET
      });
      const loader = createZcapDocumentLoader({
        didKeyDriver: driver, rootCapabilities: [root]
      });
      const zcap = await delegateCapability({
        parent: root,
        signer: alice.signer,
        toController: agent.did,
        action: ACTION,
        target: TARGET,
        expiresInSeconds: 600,
        loader
      });
      const result = await verifyDelegationChainTool({
        rootCapability: root,
        delegatedCapability: zcap,
        agentDid: agent.did,
        expectedAction: 'some-other-action',
        expectedTarget: TARGET
      });
      expect(result.authorized).toBe(false);
    });
});
