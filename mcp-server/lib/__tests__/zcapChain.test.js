/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  buildRootCapability, checkLeafController, createZcapDocumentLoader
} from '../core/zcapChain.js';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';

/**
 * @typedef {import('@digitalbazaar/did-method-key').DidKeyDriver} DidKeyDriver
 */

/**
 * Build a did:key driver wired for Ed25519.
 *
 * @returns {DidKeyDriver} A configured did:key driver.
 */
function makeDidKeyDriver() {
  const driver = didKeyDriverFactory();
  driver.use({
    multibaseMultikeyHeader: 'z6Mk',
    fromMultibase: Ed25519Multikey.from
  });
  return driver;
}

/**
 * Generate a did:key for tests.
 *
 * @param {DidKeyDriver} driver - The did:key driver.
 * @returns {Promise<string>} The generated DID.
 */
async function makeDid(driver) {
  const keyPair = await Ed25519Multikey.generate();
  const {didDocument} = await driver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  return didDocument.id;
}

describe('buildRootCapability', () => {
  it('builds a root capability for a controller and target', () => {
    const root = buildRootCapability({
      controller: 'did:key:zAlice',
      invocationTarget: 'https://resource.example/x'
    });
    expect(root.controller).toBe('did:key:zAlice');
    expect(root.invocationTarget).toBe('https://resource.example/x');
    expect(root.id).toMatch(/^urn:zcap:root:/);
  });
});

describe('createZcapDocumentLoader', () => {
  it('serves the zcap context offline', async () => {
    const loader = createZcapDocumentLoader({
      didKeyDriver: makeDidKeyDriver()
    });
    const result = await loader('https://w3id.org/zcap/v1');
    expect(result.document['@context']).toBeDefined();
  });

  it('serves the data-integrity v2 context offline', async () => {
    const loader = createZcapDocumentLoader({
      didKeyDriver: makeDidKeyDriver()
    });
    const result = await loader('https://w3id.org/security/data-integrity/v2');
    expect(result.document['@context']).toBeDefined();
  });

  it('serves a registered root capability by id', async () => {
    const root = buildRootCapability({
      controller: 'did:key:zAlice',
      invocationTarget: 'https://resource.example/x'
    });
    const loader = createZcapDocumentLoader({
      didKeyDriver: makeDidKeyDriver(),
      rootCapabilities: [root]
    });
    const result = await loader(root.id);
    expect(result.document).toEqual(root);
  });

  it('resolves a did:key controller document offline', async () => {
    const driver = makeDidKeyDriver();
    const did = await makeDid(driver);
    const loader = createZcapDocumentLoader({didKeyDriver: driver});
    const result = await loader(did);
    expect(result.document.id).toBe(did);
    expect(Array.isArray(result.document.capabilityDelegation)).toBe(true);
  });

  it('rejects an unknown URL', async () => {
    const loader = createZcapDocumentLoader({
      didKeyDriver: makeDidKeyDriver()
    });
    await expect(loader('https://example.com/nope')).rejects.toThrow();
  });
});

describe('checkLeafController', () => {
  it('passes when the leaf controller matches the expected agent', () => {
    const result = checkLeafController({
      capability: {controller: 'did:key:zAgent'},
      expectedController: 'did:key:zAgent'
    });
    expect(result.valid).toBe(true);
  });

  it('fails when the leaf controller does not match', () => {
    const result = checkLeafController({
      capability: {controller: 'did:key:zSomeoneElse'},
      expectedController: 'did:key:zAgent'
    });
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/controller|agent|match/i);
  });
});
