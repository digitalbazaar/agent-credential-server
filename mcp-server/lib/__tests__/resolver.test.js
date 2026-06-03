/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Unit tests for resolveDID — the fetch IO is stubbed, so these run offline.
 * The live-network checks live in resolver.integration.test.js.
 */
import {jest} from '@jest/globals';
import {resolveDID} from '../core/resolver.js';

/**
 * @typedef {object} FakeResponse
 * @property {boolean} ok - Whether the response is 2xx.
 * @property {number} status - The HTTP status code.
 * @property {string} statusText - The HTTP status text.
 * @property {() => Promise<unknown>} json - Resolves the JSON body.
 */

/**
 * Build a fake fetch Response.
 *
 * @param {object} options - Response options.
 * @param {boolean} [options.ok=true] - Whether the response is 2xx.
 * @param {number} [options.status=200] - The HTTP status code.
 * @param {string} [options.statusText='OK'] - The HTTP status text.
 * @param {unknown} [options.body={}] - The JSON body to return.
 * @returns {FakeResponse} A minimal Response-like object.
 */
function fakeResponse({ok = true, status = 200, statusText = 'OK', body = {}}) {
  return {ok, status, statusText, json: async () => body};
}

/**
 * A fetch-shaped jest mock: takes a URL string, resolves a FakeResponse.
 *
 * @returns {jest.Mock<(url: string, init?: unknown) => Promise<FakeResponse>>}
 *   The mock.
 */
function makeFetchMock() {
  return jest.fn(
    /** @type {(url: string, init?: unknown) => Promise<FakeResponse>} */
    (/** @type {any} */ (undefined))
  );
}

/**
 * Install a fetch mock as the global fetch.
 *
 * @param {unknown} mock - The mock to install.
 * @returns {void}
 */
function installFetch(mock) {
  globalThis.fetch = /** @type {typeof globalThis.fetch} */ (mock);
}

describe('resolveDID (did:web native path)', () => {
  /** @type {typeof globalThis.fetch} */
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    jest.clearAllMocks();
  });

  it('resolves did:web by fetching .well-known/did.json directly', async () => {
    const didDoc = {id: 'did:web:example.com'};
    const fetchMock = jest.fn(async () => fakeResponse({body: didDoc}));
    installFetch(fetchMock);

    const result = await resolveDID('did:web:example.com');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      'https://example.com/.well-known/did.json',
      expect.objectContaining({headers: {Accept: 'application/json'}})
    );
    expect(result.didDocument).toEqual(didDoc);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  it('builds a nested did.json URL for a did:web with a path', async () => {
    const fetchMock = jest.fn(async () =>
      fakeResponse({body: {id: 'did:web:example.com:agents:bot'}}));
    installFetch(fetchMock);

    await resolveDID('did:web:example.com:agents:bot');

    expect(fetchMock).toHaveBeenCalledWith(
      'https://example.com/agents/bot/did.json',
      expect.anything()
    );
  });

  it('falls back to the Universal Resolver when did:web fetch is non-2xx',
    async () => {
      const fallbackDoc = {id: 'did:web:example.com'};
      const fetchMock = makeFetchMock()
        // 1. native did:web fetch — 404
        .mockResolvedValueOnce(fakeResponse({ok: false, status: 404,
          statusText: 'Not Found'}))
        // 2. Universal Resolver fallback — succeeds
        .mockResolvedValueOnce(fakeResponse({
          body: {didDocument: fallbackDoc, didResolutionMetadata: {}}
        }));
      installFetch(fetchMock);

      const result = await resolveDID('did:web:example.com');

      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(fetchMock.mock.calls[1][0]).toMatch(/uniresolver\.io/);
      expect(result.didDocument).toEqual(fallbackDoc);
    });

  it('falls back to the Universal Resolver when did:web fetch throws',
    async () => {
      const fetchMock = makeFetchMock()
        .mockRejectedValueOnce(new Error('ECONNREFUSED'))
        .mockResolvedValueOnce(fakeResponse({
          body: {didDocument: {id: 'did:web:down.example'},
            didResolutionMetadata: {}}
        }));
      installFetch(fetchMock);

      const result = await resolveDID('did:web:down.example');

      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(result.didDocument).not.toBeNull();
    });
});

describe('resolveDID (Universal Resolver path)', () => {
  /** @type {typeof globalThis.fetch} */
  let originalFetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    jest.clearAllMocks();
  });

  it('resolves a non-web DID via the Universal Resolver', async () => {
    const body = {didDocument: {id: 'did:key:z6Mk'}, didResolutionMetadata: {}};
    const fetchMock = makeFetchMock().mockResolvedValue(fakeResponse({body}));
    installFetch(fetchMock);

    const result = await resolveDID('did:key:z6Mk');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toMatch(/uniresolver\.io/);
    expect(result.didDocument).toEqual(body.didDocument);
  });

  it('returns a null document with an error on a non-2xx response',
    async () => {
      const fetchMock = jest.fn(async () =>
        fakeResponse({ok: false, status: 500, statusText: 'Server Error'}));
      installFetch(fetchMock);

      const result = await resolveDID('did:key:zBroken');

      expect(result.didDocument).toBeNull();
      expect(result.didResolutionMetadata.error).toMatch(/500/);
    });
});
