/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Integration tests for the selective-disclosure routes via app.inject. They
 * exercise the genuine path: a real SD wallet derives a real reveal document,
 * the real verify tool checks it. The key property — the full credential (the
 * birthdate especially) never crosses to the client — is asserted directly.
 */
import {buildApp} from '../server.js';
import {jest} from '@jest/globals';

// real SD derive/verify (ecdsa-sd-2023 and bbs-2023) is CPU-heavy; give the
// suite headroom over the 5s default so it stays reliable under parallel load
jest.setTimeout(30000);

/** @type {import('fastify').FastifyInstance} */
let app;

beforeAll(async () => {
  app = buildApp();
  await app.ready();
});

afterAll(async () => {
  await app.close();
});

describe('POST /api/sd/disclose/:mode', () => {
  it('discloses only age_over_21, keeping the rest in the wallet', async () => {
    const res = await app.inject({
      method: 'POST', url: '/api/sd/disclose/linkable'
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.cryptosuite).toBe('ecdsa-sd-2023');
    expect(body.disclosedClaims).toEqual(['age_over_21']);
    expect(body.hiddenCount).toBe(4);
    // the reveal exists and discloses only age_over_21; the hidden claim
    // VALUES (the birthdate especially) must never cross to the client. The
    // heldClaims manifest lists names by design, so assert on values + the
    // reveal's own subject, not on the name "birthdate" appearing in metadata.
    expect(body.reveal).toBeDefined();
    expect(body.reveal.credentialSubject).toEqual({
      id: body.agentDid, age_over_21: true
    });
    expect(JSON.stringify(body)).not.toMatch(/2000-01-01/);
    expect(JSON.stringify(body)).not.toMatch(/Pat Holder/);
  });

  it('derives two uncorrelated proofs in unlinkable (bbs-2023) mode',
    async () => {
      const res = await app.inject({
        method: 'POST', url: '/api/sd/disclose/unlinkable'
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.cryptosuite).toBe('bbs-2023');
      expect(body.reveal).toBeDefined();
      expect(body.secondReveal).toBeDefined();
      // two derivations from one credential must not be byte-identical (their
      // proofs differ) — that is the unlinkability the UI demonstrates
      expect(JSON.stringify(body.reveal.proof))
        .not.toEqual(JSON.stringify(body.secondReveal.proof));
    });

  it('returns 404 for an unknown mode', async () => {
    const res = await app.inject({
      method: 'POST', url: '/api/sd/disclose/nope'
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toMatch(/unknown/i);
  });
});

describe('POST /api/sd/verify', () => {
  it('verifies a freshly derived reveal document', async () => {
    const disclosed = (await app.inject({
      method: 'POST', url: '/api/sd/disclose/linkable'
    })).json();
    const res = await app.inject({
      method: 'POST',
      url: '/api/sd/verify',
      payload: {reveal: disclosed.reveal, cryptosuite: disclosed.cryptosuite}
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().valid).toBe(true);
  });

  it('rejects a body missing the reveal with 400', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/sd/verify',
      payload: {cryptosuite: 'ecdsa-sd-2023'}
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toMatch(/reveal/i);
  });
});
