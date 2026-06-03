/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {jest} from '@jest/globals';

/**
 * @typedef {import('../core/resolver.js').ResolutionResult} ResolutionResult
 */

// the network resolver is mocked so the fallback path is deterministic
/** @type {jest.MockedFunction<(did: string) => Promise<ResolutionResult>>} */
const mockResolveDID = jest.fn();
jest.unstable_mockModule('../core/resolver.js', () => ({
  resolveDID: mockResolveDID
}));

const Ed25519Multikey = await import('@digitalbazaar/ed25519-multikey');
const {driver: didKeyDriverFactory} =
  await import('@digitalbazaar/did-method-key');
const {resolveAgentKey} = await import('../tools/didKeyContext.js');

/**
 * Generate a did:key and the raw public key it encodes.
 *
 * @returns {Promise<{did: string, publicKey: Uint8Array}>} The DID and key.
 */
async function makeDidKey() {
  const driver = didKeyDriverFactory();
  driver.use({
    multibaseMultikeyHeader: 'z6Mk',
    fromMultibase: Ed25519Multikey.from
  });
  const keyPair = await Ed25519Multikey.generate();
  const {didDocument} = await driver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const {publicKey} = await keyPair.export({publicKey: true, raw: true});
  if(!publicKey) {
    throw new Error('export did not return a public key');
  }
  return {did: didDocument.id, publicKey: new Uint8Array(publicKey)};
}

describe('resolveAgentKey', () => {
  beforeEach(() => jest.clearAllMocks());

  it('resolves a did:key offline without the network resolver', async () => {
    const {did, publicKey} = await makeDidKey();
    const key = await resolveAgentKey(did);
    expect(key).toEqual(publicKey);
    expect(mockResolveDID).not.toHaveBeenCalled();
  });

  it('falls back to the network resolver for non-did:key DIDs', async () => {
    const {publicKey} = await makeDidKey();
    const toB64u = (/** @type {Uint8Array} */ b) =>
      Buffer.from(b).toString('base64url');
    mockResolveDID.mockResolvedValue({
      didDocument: {
        id: 'did:web:example.com',
        verificationMethod: [{
          id: 'did:web:example.com#key-1',
          type: 'JsonWebKey2020',
          controller: 'did:web:example.com',
          publicKeyJwk: {kty: 'OKP', crv: 'Ed25519', x: toB64u(publicKey)}
        }]
      },
      didResolutionMetadata: {}
    });
    const key = await resolveAgentKey('did:web:example.com');
    expect(key).toEqual(publicKey);
    expect(mockResolveDID).toHaveBeenCalledWith('did:web:example.com');
  });

  it('returns null when a non-did:key DID cannot be resolved', async () => {
    mockResolveDID.mockResolvedValue({
      didDocument: null,
      didResolutionMetadata: {error: 'notFound'}
    });
    const key = await resolveAgentKey('did:web:missing.example');
    expect(key).toBeNull();
  });
});
