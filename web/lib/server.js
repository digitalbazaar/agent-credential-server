/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The Fastify HTTP shell for the web demo. This is the imperative shell: it
 * wires routes to the framework-agnostic handlers and starts the server. All
 * verification logic lives behind the handlers, in the already-tested
 * mcp-server core. Build the app with buildApp() (testable via app.inject);
 * start() runs it.
 *
 * KYA-OS R-X-1/R-X-2: the handlers run the authoritative checks and sanitize
 * every response; this file adds no logic that could bypass them.
 */
import {getScenario, postCheckDelegation} from './handlers.js';
import {postDisclose, postVerifyDisclosure} from './sdHandlers.js';
import {existsSync} from 'node:fs';
import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import {fileURLToPath} from 'node:url';
import {scenarioNames} from './scenarios.js';

// the built Vue client (web/client → web/public); served as static files when
// it has been built. Absent in a fresh checkout or in the test run, which is
// fine — the API routes work without it.
const PUBLIC_DIR = fileURLToPath(new URL('../public', import.meta.url));

/**
 * Build the Fastify app with the API routes registered. Does not listen — the
 * caller starts it (or injects requests in tests).
 *
 * @param {object} [options] - Fastify options such as a logger setting.
 * @returns {import('fastify').FastifyInstance} The configured app.
 */
export function buildApp(options = {}) {
  const app = Fastify(options);

  // list the available scenarios (lets the UI populate its picker)
  app.get('/api/scenarios', async () => ({scenarios: scenarioNames()}));

  // build one scenario: a real signed credential + DIDs, keys stripped
  app.get('/api/scenario/:name', async (request, reply) => {
    const {name} = /** @type {{name: string}} */ (request.params);
    const {status, body} = await getScenario(name);
    return reply.code(status).send(body);
  });

  // verify a credential against a requested action via checkDelegation
  app.post('/api/check-delegation', async (request, reply) => {
    const {status, body} = await postCheckDelegation(
      /** @type {any} */ (request.body));
    return reply.code(status).send(body);
  });

  // derive a minimal selective-disclosure reveal (the full credential stays
  // server-side in the wallet); mode is 'linkable' | 'unlinkable'
  app.post('/api/sd/disclose/:mode', async (request, reply) => {
    const {mode} = /** @type {{mode: string}} */ (request.params);
    const {status, body} = await postDisclose(mode);
    return reply.code(status).send(body);
  });

  // verify a reveal document's derived selective-disclosure proof
  app.post('/api/sd/verify', async (request, reply) => {
    const {status, body} = await postVerifyDisclosure(
      /** @type {any} */ (request.body));
    return reply.code(status).send(body);
  });

  // serve the built SPA (and its SPA fallback) only if it has been built
  if(existsSync(PUBLIC_DIR)) {
    app.register(fastifyStatic, {root: PUBLIC_DIR});
  }

  return app;
}

/**
 * Start the server on the configured host and port.
 *
 * @returns {Promise<void>}
 */
export async function start() {
  const app = buildApp({logger: true});
  const port = Number(process.env.PORT ?? 3000);
  const host = process.env.HOST ?? '127.0.0.1';
  await app.listen({port, host});
}

// run only when executed directly, not when imported by a test
if(process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  start().catch(err => {
    console.error('Failed to start web server:', err);
    process.exit(1);
  });
}
