/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The simulated Cloudflare resource server: a fail-closed migration pipeline
 * (verify admin credential -> check role -> stage records -> approval gate ->
 * single-use cutover). The real Cloudflare token never exists here; everything
 * is simulated. These tests exercise the decision logic offline.
 */
import {createCloudflareServer} from '../cloudflare.js';

const ZONE = 'sandbox.example';

describe('createCloudflareServer: single-use cutover', () => {
  it('consumes a cutover capability id once, denies a replay', () => {
    const server = createCloudflareServer();
    const capId = 'urn:uuid:cutover-1';
    const first = server.recordCutover(capId);
    expect(first.ok).toBe(true);
    const replay = server.recordCutover(capId);
    expect(replay.ok).toBe(false);
    expect(replay.reason).toMatch(/already|used|consume/i);
  });

  it('cuts over at most once per migration, even with a different capability',
    () => {
      // idempotency, not per-id: a second cutover is denied regardless of the
      // capability id (a re-approval mints a fresh id; the effect happens once)
      const server = createCloudflareServer();
      expect(server.recordCutover('urn:uuid:a').ok).toBe(true);
      const second = server.recordCutover('urn:uuid:b');
      expect(second.ok).toBe(false);
      expect(second.reason).toMatch(/already cut over|once/i);
    });
});

describe('createCloudflareServer: staging', () => {
  it('returns a diff of the records it would create', () => {
    const server = createCloudflareServer();
    const records = [
      {type: 'A', name: ZONE, content: '192.0.2.1'},
      {type: 'CNAME', name: `www.${ZONE}`, content: ZONE}
    ];
    const result = server.stage({zone: ZONE, records});
    expect(result.staged).toBe(true);
    expect(result.diff).toHaveLength(2);
    expect(result.diff[0]).toMatchObject({action: 'create', type: 'A'});
  });

  it('does not perform a real change (simulation only)', () => {
    const server = createCloudflareServer();
    const result = server.stage({zone: ZONE, records: []});
    expect(result.simulated).toBe(true);
  });
});
