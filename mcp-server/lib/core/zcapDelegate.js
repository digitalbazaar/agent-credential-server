/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/*
 * Authorization-capability (zcap) delegation signing helpers: generate an
 * Ed25519 did:key controller, and sign a scoped delegated capability from a
 * parent to that controller. These compose with the verify-side helpers in
 * zcapChain.js (buildRootCapability / createZcapDocumentLoader) and were
 * previously duplicated in the demo scenario builders and verifyChain.test.js.
 *
 * The did:key driver is injected, so this file performs no resolution IO of
 * its own; jsigs.sign serves all documents through the provided loader.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {CapabilityDelegation} from '@digitalbazaar/zcap';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as eddsaRdfc2022}
  from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import jsigs from 'jsonld-signatures';

/**
 * @typedef {import('@digitalbazaar/did-method-key').DidKeyDriver} DidKeyDriver
 * @typedef {Record<string, unknown> & {id: string,
 *   controller?: string, allowedAction?: string | string[]}} DelegatedZcap
 */

/**
 * @typedef {object} DelegationController
 * @property {string} did - The controller's did:key DID.
 * @property {object} signer - The capabilityDelegation signer for the key.
 */

/**
 * Generate an Ed25519 did:key controller with a capabilityDelegation signer.
 * The controller can act as either a delegator (signing a child capability) or
 * a delegate (the recipient of one).
 *
 * @param {DidKeyDriver} driver - The Ed25519-wired did:key driver.
 * @returns {Promise<DelegationController>} The controller DID and its signer.
 */
export async function makeDelegationController(driver) {
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
 * @typedef {object} DelegateCapabilityInput
 * @property {{id: string}} parent - The parent capability (root or delegated).
 * @property {object} signer - The delegator's signer (the parent controller).
 * @property {string} toController - The recipient (delegate) DID.
 * @property {string} action - The single allowed action.
 * @property {string} target - The invocation target (protected resource URL).
 * @property {number} expiresInSeconds - Lifetime from now, in seconds.
 * @property {(url: string) => Promise<unknown>} loader - The zcap document
 *   loader (typically from createZcapDocumentLoader).
 */

/**
 * Sign a delegated capability from a parent to a controller, scoped to one
 * action and one invocation target, expiring after the given lifetime.
 *
 * @param {DelegateCapabilityInput} input - The delegation parameters.
 * @returns {Promise<DelegatedZcap>} The signed delegated capability.
 */
export async function delegateCapability(input) {
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
  return /** @type {DelegatedZcap} */ (signed);
}
