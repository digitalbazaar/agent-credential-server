/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Integration tests for the applied-demo runner via app.inject. The mock model
 * drives the genuine demo tools over a real scenario; the route returns the
 * tool-call trace and the authoritative tool decisions. The key property —
 * the decision comes from the tools, recorded server-side, not from model prose
 * — is asserted by reading the decisions array.
 */
import {buildApp} from '../server.js';
import {jest} from '@jest/globals';

// real VC + zcap sign/verify across a demo is CPU-heavy; give the suite
// headroom over the 5s default so it stays reliable under parallel load
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

describe('GET /api/demos', () => {
  it('lists the applied demos', async () => {
    const res = await app.inject({method: 'GET', url: '/api/demos'});
    expect(res.statusCode).toBe(200);
    expect(res.json().demos).toEqual(
      expect.arrayContaining(['cloudflare', 'dmv']));
  });
});

describe('POST /api/run-demo/dmv', () => {
  it('runs the DMV demo and grants via the register_vehicle tool', async () => {
    const res = await app.inject({method: 'POST', url: '/api/run-demo/dmv'});
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.toolCalls).toContain('register_vehicle');
    const decision = body.decisions.find(
      (/** @type {any} */ d) => d.name === 'register_vehicle');
    expect(decision.output.granted).toBe(true);
    expect(decision.output.confirmation).toMatch(/^CA-REG-\d{6}$/);
  });
});

describe('POST /api/run-demo/cloudflare', () => {
  it('runs the Cloudflare demo: stages then cuts over after approval',
    async () => {
      const res = await app.inject({
        method: 'POST', url: '/api/run-demo/cloudflare'
      });
      expect(res.statusCode).toBe(200);
      const body = res.json();
      expect(body.toolCalls).toContain('verify_admin');
      expect(body.toolCalls).toContain('cutover');
      const cutover = body.decisions.find(
        (/** @type {any} */ d) => d.name === 'cutover');
      expect(cutover.output.authorized).toBe(true);
    });
});

describe('POST /api/run-demo/:name', () => {
  it('returns 404 for an unknown demo', async () => {
    const res = await app.inject({method: 'POST', url: '/api/run-demo/nope'});
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toMatch(/unknown/i);
  });

  it('never leaks key material in the trace', async () => {
    const res = await app.inject({method: 'POST', url: '/api/run-demo/dmv'});
    const raw = res.payload;
    expect(raw).not.toMatch(/privateKey/i);
    expect(raw).not.toMatch(/secretKeyMultibase/i);
    expect(raw).not.toMatch(/"signer"/);
  });
});
