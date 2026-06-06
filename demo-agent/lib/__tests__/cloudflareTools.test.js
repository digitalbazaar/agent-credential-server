/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Tool-layer tests for the Cloudflare migration flow. Each tool composes the
 * genuine mcp-server verification tools and the simulated resource server. The
 * agent orchestrates them, but the tools are authoritative — a missing or
 * out-of-scope capability denies, and the cutover gate (Model A) is
 * unbypassable because the agent holds no cutover capability until approval.
 */
import {buildCloudflareTools} from '../cloudflareTools.js';
import {buildMigrationScenario} from '../cloudflareScenarios.js';
import {createCloudflareServer} from '../cloudflare.js';

/**
 * Build a fresh tool set bound to a fresh scenario + server.
 *
 * @param {object} [options] - Scenario options such as a role override.
 * @returns {Promise<{tools: any, scenario: any, server: any}>} The wiring.
 */
async function setup(options) {
  const scenario = await buildMigrationScenario(options);
  const server = createCloudflareServer();
  const tools = buildCloudflareTools({scenario, server});
  return {tools, scenario, server};
}

describe('verify_admin', () => {
  it('authorizes a domain-admin credential', async () => {
    const {tools} = await setup();
    const r = await tools.verify_admin.execute({});
    expect(r.authorized).toBe(true);
  });

  it('denies a non-admin role', async () => {
    const {tools} = await setup({role: 'viewer'});
    const r = await tools.verify_admin.execute({});
    expect(r.authorized).toBe(false);
  });
});

describe('stage_records', () => {
  it('stages when the stage delegation is valid, with a diff', async () => {
    const {tools} = await setup();
    const r = await tools.stage_records.execute({
      records: [{type: 'A', name: 'sandbox.example', content: '192.0.2.1'}]
    });
    expect(r.staged).toBe(true);
    expect(r.diff).toHaveLength(1);
  });
});

describe('cutover gate (Model A)', () => {
  it('cannot cut over before approval (no capability held)', async () => {
    const {tools} = await setup();
    // the agent has not been approved; it holds no cutover capability
    const r = await tools.cutover.execute({});
    expect(r.authorized).toBe(false);
    expect(r.reason).toMatch(/approv|capab/i);
  });

  it('cuts over after approval, then denies a replay (single-use)',
    async () => {
      const {tools} = await setup();
      await tools.request_cutover_approval.execute({});
      const first = await tools.cutover.execute({});
      expect(first.authorized).toBe(true);
      const replay = await tools.cutover.execute({});
      expect(replay.authorized).toBe(false);
      expect(replay.reason).toMatch(/single-use|already|used/i);
    });
});
