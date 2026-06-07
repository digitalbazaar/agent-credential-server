/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Integration tests for the Fastify shell via app.inject (no real socket).
 * These exercise the genuine path: real scenario builders, the real
 * checkDelegation tool, and the sanitizer. The leakage canary runs against a
 * live response. Adversarial inputs (unknown scenario, malformed body, a
 * tampered credential) are covered alongside the happy path.
 */
import {buildApp} from '../server.js';
import {FORBIDDEN_KEYS} from '../sanitize.js';
import {jest} from '@jest/globals';

// real VC issue/verify is CPU-heavy; give the suite headroom over the 5s
// default so it stays reliable under parallel CI load
jest.setTimeout(15000);

/** @type {import('fastify').FastifyInstance} */
let app;

beforeAll(async () => {
  app = buildApp();
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

/**
 * Recursively assert no forbidden key appears anywhere in a value.
 *
 * @param {unknown} value - The value to scan.
 * @returns {void}
 */
function assertNoForbiddenKeys(value) {
  if(Array.isArray(value)) {
    value.forEach(assertNoForbiddenKeys);
    return;
  }
  if(value !== null && typeof value === 'object') {
    for(const [key, child] of Object.entries(value)) {
      expect(FORBIDDEN_KEYS).not.toContain(key.toLowerCase());
      assertNoForbiddenKeys(child);
    }
  }
}

describe('GET /api/scenarios', () => {
  it('lists the available scenario names', async () => {
    const res = await app.inject({method: 'GET', url: '/api/scenarios'});
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(Array.isArray(body.scenarios)).toBe(true);
    expect(body.scenarios).toContain('valid');
    expect(body.scenarios).toContain('tampered');
  });
});

describe('GET /api/scenario/:name', () => {
  it('returns a built scenario with a credential and no key material',
    async () => {
      const res = await app.inject({method: 'GET', url: '/api/scenario/valid'});
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.name).toBe('valid');
      expect(body.expected).toBe('GRANTED');
      expect(body.scenario.credential).toBeDefined();
      expect(body.scenario.agentDid).toMatch(/^did:key:/);
      assertNoForbiddenKeys(body);
    });

  it('strips key material from a DMV-style scenario with signers', async () => {
    // authn scenario carries a real agent keypair internally; the response
    // must not leak it
    const res = await app.inject({method: 'GET', url: '/api/scenario/authn'});
    expect(res.statusCode).toBe(200);
    assertNoForbiddenKeys(res.json());
  });

  it('returns 404 for an unknown scenario', async () => {
    const res = await app.inject({method: 'GET', url: '/api/scenario/nope'});
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toMatch(/unknown/i);
  });
});

describe('POST /api/check-delegation', () => {
  it('grants a valid scenario end to end', async () => {
    const built = (await app.inject({
      method: 'GET', url: '/api/scenario/valid'
    })).json();
    const res = await app.inject({
      method: 'POST',
      url: '/api/check-delegation',
      payload: {
        agentDid: built.scenario.agentDid,
        requestedAction: 'access:age-restricted-content',
        credential: built.scenario.credential,
        requiredClaims: built.scenario.requiredClaims
      }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().authorized).toBe(true);
  });

  it('denies a tampered scenario end to end', async () => {
    const built = (await app.inject({
      method: 'GET', url: '/api/scenario/tampered'
    })).json();
    const res = await app.inject({
      method: 'POST',
      url: '/api/check-delegation',
      payload: {
        agentDid: built.scenario.agentDid,
        requestedAction: 'access:age-restricted-content',
        credential: built.scenario.credential,
        requiredClaims: built.scenario.requiredClaims ?? {}
      }
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().authorized).toBe(false);
  });

  it('rejects a body missing the credential with 400', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/check-delegation',
      payload: {agentDid: 'did:key:z6Mk', requestedAction: 'x'}
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toMatch(/credential/i);
  });

  it('rejects a missing agentDid with 400', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/check-delegation',
      payload: {requestedAction: 'x', credential: {}}
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toMatch(/agentDid/i);
  });
});
