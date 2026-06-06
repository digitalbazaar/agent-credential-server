/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * A simulated Cloudflare resource server for the migration demo. It performs
 * NO real Cloudflare or registrar calls — every step returns what it *would*
 * do. The real Cloudflare API token would live only here, never with the
 * agent; the agent holds only scoped zcap capabilities (see
 * docs/cloudflare-migration-spec.md).
 *
 * This module is the simulated server's state + simulated effects (the
 * single-use cutover store and the staging diff). The authorization pipeline
 * that gates these effects (verify admin VC, verify the scoped delegation)
 * composes the genuine mcp-server tools in the migration flow.
 */

/**
 * @typedef {object} DnsRecord
 * @property {string} type - The record type (A, CNAME, …).
 * @property {string} name - The record name.
 * @property {string} content - The record value.
 */

/**
 * @typedef {object} StageResult
 * @property {boolean} staged - Whether the records were staged.
 * @property {boolean} simulated - Always true; no real change is made.
 * @property {Array<{action: string, type: string, name: string,
 *   content: string}>} diff - The diff of records that would be created.
 */

/**
 * @typedef {object} CutoverRecord
 * @property {boolean} ok - Whether the cutover id was newly consumed.
 * @property {string} [reason] - The rejection reason when ok is false.
 */

/**
 * @typedef {object} CloudflareServer
 * @property {(input: {zone: string, records: DnsRecord[]}) => StageResult}
 *   stage - Stage DNS records (simulated); returns a diff.
 * @property {(cutoverCapId: string) => CutoverRecord} recordCutover - Consume a
 *   cutover capability id exactly once (single-use enforcement).
 */

/**
 * Create a fresh simulated Cloudflare resource server. State (the consumed
 * cutover ids) lives here, in the verifier — not with the agent.
 *
 * @returns {CloudflareServer} The simulated server.
 */
export function createCloudflareServer() {
  // The irreversible nameserver cutover happens AT MOST ONCE per migration —
  // this is an idempotency guard, not a per-capability check. Keying on the
  // capability id alone would be defeated by re-approval (a fresh approval
  // mints a new id), letting the agent cut over twice. The security property
  // we want is "the irreversible effect occurs once", so the server records
  // that a cutover has happened at all. (A production system would add
  // transactional rollback for partial failures; see the spec.)
  let cutoverDone = false;
  /** @type {string | null} the capability id that performed the cutover */
  let cutoverCapId = null;

  return Object.freeze({
    stage({records}) {
      return {
        staged: true,
        simulated: true,
        diff: records.map(r => ({
          action: 'create', type: r.type, name: r.name, content: r.content
        }))
      };
    },

    recordCutover(capId) {
      if(cutoverDone) {
        const sameCap = capId === cutoverCapId;
        return {
          ok: false,
          reason: sameCap ?
            `Cutover capability ${capId} already used (single-use)` :
            'This migration has already cut over; nameservers switch once.'
        };
      }
      cutoverDone = true;
      cutoverCapId = capId;
      return {ok: true};
    }
  });
}
