/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {
  AGENT_CREDENTIAL_CONTEXT, AGENT_CREDENTIAL_CONTEXT_URL,
  createDocumentLoader
} from '../core/documentLoader.js';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';
import {fileURLToPath} from 'node:url';
import {jest} from '@jest/globals';
import {readFileSync} from 'node:fs';

/**
 * @typedef {import('@digitalbazaar/did-method-key').DidKeyDriver} DidKeyDriver
 * @typedef {import('../core/documentLoader.js').DocumentLoader} DocumentLoader
 * @typedef {import('../core/documentLoader.js').DocumentLoaderResult}
 *   DocumentLoaderResult
 */

/**
 * Build a did:key driver wired for Ed25519, as the tools do.
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
 * Generate a did:key and its DID document for tests.
 *
 * @param {DidKeyDriver} driver - The did:key driver.
 * @returns {Promise<{did: string, vmId: string}>} The DID and key id.
 */
async function makeDidKey(driver) {
  const keyPair = await Ed25519Multikey.generate();
  const {didDocument} = await driver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  return {did: didDocument.id, vmId: didDocument.verificationMethod[0].id};
}

describe('createDocumentLoader: did:key', () => {
  it('resolves a did:key URL to an unwrapped document', async () => {
    const driver = makeDidKeyDriver();
    const {did} = await makeDidKey(driver);
    const loader = createDocumentLoader({didKeyDriver: driver});

    const result = await loader(did);
    expect(result.documentUrl).toBe(did);
    expect(result.contextUrl).toBeNull();
    // the document must be the DID document itself, NOT wrapped as
    // {didDocument: ...} — that wrapping breaks Data Integrity verification
    expect(result.document).not.toHaveProperty('didDocument');
    expect(result.document.id).toBe(did);
    expect(Array.isArray(result.document.verificationMethod)).toBe(true);
  });

  it('resolves a did:key #fragment to the verification method', async () => {
    const driver = makeDidKeyDriver();
    const {vmId} = await makeDidKey(driver);
    const loader = createDocumentLoader({didKeyDriver: driver});

    const result = await loader(vmId);
    expect(result.document.id).toBe(vmId);
    expect(typeof result.document.publicKeyMultibase).toBe('string');
  });
});

describe('createDocumentLoader: bundled contexts', () => {
  it('serves the agent credential context offline', async () => {
    const fallback = /** @type {DocumentLoader} */ (jest.fn());
    const loader = createDocumentLoader({
      didKeyDriver: makeDidKeyDriver(),
      fallbackLoader: fallback
    });

    const result = await loader(AGENT_CREDENTIAL_CONTEXT_URL);
    expect(result.documentUrl).toBe(AGENT_CREDENTIAL_CONTEXT_URL);
    expect(result.document).toEqual(AGENT_CREDENTIAL_CONTEXT);
    // a bundled context must never hit the network fallback
    expect(fallback).not.toHaveBeenCalled();
  });

  it('serves exactly the canonical context file from disk', () => {
    // the bytes served must match the file that will be published to w3id.org
    const filePath = fileURLToPath(new URL(
      '../../contexts/agent-credential-v1.jsonld', import.meta.url
    ));
    const onDisk = JSON.parse(readFileSync(filePath, 'utf8'));
    expect(AGENT_CREDENTIAL_CONTEXT).toEqual(onDisk);
    expect(onDisk['@context']['@vocab'])
      .toBe('https://w3id.org/agent-credential#');
  });

  it('serves the VC 2.0 context via the default loader fallback', async () => {
    // the VC 2.0 context is served offline by @digitalbazaar/vc's default
    // loader, which the tool layer injects as the fallback
    const {defaultDocumentLoader} = await import('@digitalbazaar/vc');
    const loader = createDocumentLoader({
      didKeyDriver: makeDidKeyDriver(),
      fallbackLoader: defaultDocumentLoader
    });

    const result = await loader('https://www.w3.org/ns/credentials/v2');
    expect(result.document['@context']).toBeDefined();
  });
});

describe('createDocumentLoader: caching and fallback', () => {
  it('returns the same cached object on repeated did:key loads', async () => {
    const driver = makeDidKeyDriver();
    const {did} = await makeDidKey(driver);
    const loader = createDocumentLoader({didKeyDriver: driver});

    const first = await loader(did);
    const second = await loader(did);
    expect(second).toBe(first);
  });

  it('delegates an unknown URL to the injected fallback loader', async () => {
    /** @type {DocumentLoaderResult} */
    const fallbackDoc = {
      contextUrl: null,
      documentUrl: 'https://example.com/thing',
      document: {hello: 'world'}
    };
    /** @type {jest.MockedFunction<DocumentLoader>} */
    const fallback = jest.fn();
    fallback.mockResolvedValue(fallbackDoc);
    const loader = createDocumentLoader({
      didKeyDriver: makeDidKeyDriver(),
      fallbackLoader: fallback
    });

    const result = await loader('https://example.com/thing');
    expect(result).toEqual(fallbackDoc);
    expect(fallback).toHaveBeenCalledWith('https://example.com/thing');
  });

  it('rejects an unknown URL when no fallback is provided', async () => {
    const loader = createDocumentLoader({didKeyDriver: makeDidKeyDriver()});
    await expect(loader('https://example.com/nope')).rejects.toThrow(
      /document loader|not found|unsupported/i
    );
  });
});
