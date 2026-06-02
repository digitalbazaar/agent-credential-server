/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {buildRootCapability, createZcapDocumentLoader}
  from '../core/zcapChain.js';
import {CapabilityDelegation} from '@digitalbazaar/zcap';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as eddsaRdfc2022}
  from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';
import {verifyDelegationChainTool} from '../tools/verifyChain.js';
import jsigs from 'jsonld-signatures';

const TARGET = 'https://resource.example/age-gated';
const ACTION = 'access:age-restricted-content';

const driver = didKeyDriverFactory();
driver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519Multikey.from
});

/**
 * Make a did:key controller with a delegation signer.
 *
 * @returns {Promise<{did: string, signer: object}>} The controller.
 */
async function makeController() {
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
 * Delegate a capability from a parent to a new controller.
 *
 * @param {object} input - Delegation parameters.
 * @param {{id: string}} input.parent - The parent capability (root/delegated).
 * @param {object} input.signer - The delegator's signer.
 * @param {string} input.toController - The recipient DID.
 * @param {string} input.expires - The expiry, ISO 8601.
 * @param {(url: string) => Promise<unknown>} input.loader - The doc loader.
 * @returns {Promise<Record<string, unknown> & {id: string}>} The signed zcap.
 */
async function delegate(input) {
  const {parent, signer, toController, expires, loader} = input;
  const zcap = {
    '@context': ['https://w3id.org/zcap/v1'],
    id: `urn:uuid:${crypto.randomUUID()}`,
    parentCapability: parent.id,
    invocationTarget: TARGET,
    controller: toController,
    allowedAction: ACTION,
    expires
  };
  const signed = await jsigs.sign(zcap, {
    documentLoader: loader,
    suite: new DataIntegrityProof({signer, cryptosuite: eddsaRdfc2022}),
    purpose: new CapabilityDelegation({parentCapability: parent})
  });
  return /** @type {Record<string, unknown> & {id: string}} */ (signed);
}

describe('verifyDelegationChainTool', () => {
  it('authorizes a valid 2-hop chain', async () => {
    const alice = await makeController();
    const bob = await makeController();
    const expires = new Date(Date.now() + 3600000).toISOString();
    const root = buildRootCapability({
      controller: alice.did, invocationTarget: TARGET
    });
    const loader = createZcapDocumentLoader({
      didKeyDriver: driver, rootCapabilities: [root]
    });
    const bobZcap = await delegate({
      parent: root, signer: alice.signer, toController: bob.did, expires, loader
    });

    const result = await verifyDelegationChainTool({
      rootCapability: root,
      delegatedCapability: bobZcap,
      agentDid: bob.did,
      expectedAction: ACTION,
      expectedTarget: TARGET
    });
    expect(result.authorized).toBe(true);
  });

  it('authorizes a valid 3-hop chain', async () => {
    const alice = await makeController();
    const bob = await makeController();
    const carol = await makeController();
    const expires = new Date(Date.now() + 3600000).toISOString();
    const root = buildRootCapability({
      controller: alice.did, invocationTarget: TARGET
    });
    const loader = createZcapDocumentLoader({
      didKeyDriver: driver, rootCapabilities: [root]
    });
    const bobZcap = await delegate({
      parent: root, signer: alice.signer, toController: bob.did, expires, loader
    });
    const carolZcap = await delegate({
      parent: bobZcap, signer: bob.signer, toController: carol.did,
      expires, loader
    });

    const result = await verifyDelegationChainTool({
      rootCapability: root,
      delegatedCapability: carolZcap,
      agentDid: carol.did,
      expectedAction: ACTION,
      expectedTarget: TARGET
    });
    expect(result.authorized).toBe(true);
  });

  it('denies when the leaf controller is not the expected agent', async () => {
    const alice = await makeController();
    const bob = await makeController();
    const expires = new Date(Date.now() + 3600000).toISOString();
    const root = buildRootCapability({
      controller: alice.did, invocationTarget: TARGET
    });
    const loader = createZcapDocumentLoader({
      didKeyDriver: driver, rootCapabilities: [root]
    });
    const bobZcap = await delegate({
      parent: root, signer: alice.signer, toController: bob.did, expires, loader
    });

    const result = await verifyDelegationChainTool({
      rootCapability: root,
      delegatedCapability: bobZcap,
      agentDid: 'did:key:z6MkSomeoneElse',
      expectedAction: ACTION,
      expectedTarget: TARGET
    });
    expect(result.authorized).toBe(false);
    expect(result.reason).toMatch(/controller|agent|match/i);
  });

  it('denies a tampered delegation', async () => {
    const alice = await makeController();
    const bob = await makeController();
    const expires = new Date(Date.now() + 3600000).toISOString();
    const root = buildRootCapability({
      controller: alice.did, invocationTarget: TARGET
    });
    const loader = createZcapDocumentLoader({
      didKeyDriver: driver, rootCapabilities: [root]
    });
    const bobZcap = await delegate({
      parent: root, signer: alice.signer, toController: bob.did, expires, loader
    });
    // mutate the signed target — the delegation proof no longer verifies
    const tampered = JSON.parse(JSON.stringify(bobZcap));
    tampered.invocationTarget = 'https://resource.example/other';

    const result = await verifyDelegationChainTool({
      rootCapability: root,
      delegatedCapability: tampered,
      agentDid: bob.did,
      expectedAction: ACTION,
      expectedTarget: TARGET
    });
    expect(result.authorized).toBe(false);
  });

  it('denies when the root capability does not match', async () => {
    const alice = await makeController();
    const bob = await makeController();
    const mallory = await makeController();
    const expires = new Date(Date.now() + 3600000).toISOString();
    const root = buildRootCapability({
      controller: alice.did, invocationTarget: TARGET
    });
    // a different root the verifier will expect
    const wrongRoot = buildRootCapability({
      controller: mallory.did, invocationTarget: 'https://resource.example/x'
    });
    const loader = createZcapDocumentLoader({
      didKeyDriver: driver, rootCapabilities: [root, wrongRoot]
    });
    const bobZcap = await delegate({
      parent: root, signer: alice.signer, toController: bob.did, expires, loader
    });

    const result = await verifyDelegationChainTool({
      rootCapability: wrongRoot,
      delegatedCapability: bobZcap,
      agentDid: bob.did,
      expectedAction: ACTION,
      expectedTarget: TARGET
    });
    expect(result.authorized).toBe(false);
  });

  it('denies a delegation whose expiry was extended', async () => {
    const alice = await makeController();
    const bob = await makeController();
    const expires = new Date(Date.now() + 3600000).toISOString();
    const root = buildRootCapability({
      controller: alice.did, invocationTarget: TARGET
    });
    const loader = createZcapDocumentLoader({
      didKeyDriver: driver, rootCapabilities: [root]
    });
    const bobZcap = await delegate({
      parent: root, signer: alice.signer, toController: bob.did, expires, loader
    });
    // tamper the expiry to a later time — the signed proof no longer matches
    const tampered = JSON.parse(JSON.stringify(bobZcap));
    tampered.expires = new Date(Date.now() + 7200000).toISOString();

    const result = await verifyDelegationChainTool({
      rootCapability: root,
      delegatedCapability: tampered,
      agentDid: bob.did,
      expectedAction: ACTION,
      expectedTarget: TARGET
    });
    expect(result.authorized).toBe(false);
  });
});
