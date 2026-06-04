/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The selective-disclosure tool set for the demo agent. Two tools wire the
 * holder Model B flow: `request_disclosure` calls the wallet seam to derive a
 * minimal reveal document (the agent never sees the full credential), and
 * `verify_disclosure` checks the derived proof via the genuine mcp-server tool.
 * The agent orchestrates them but is never the authority on the verdict.
 */
import {tool} from 'ai';
import {verifyDisclosureTool} from 'mcp-server/lib/tools/verifyDisclosure.js';
import {z} from 'zod';

/**
 * @typedef {import('./wallet.js').Wallet} Wallet
 * @typedef {import('mcp-server/lib/core/vcSd.js').VerifyDisclosureResult}
 *   VerifyDisclosureResult
 */

/**
 * @typedef {object} BuildSdToolsOptions
 * @property {Wallet} wallet - The holder wallet for request_disclosure.
 * @property {(reveal: Record<string, unknown>) => void} [onDisclosure] -
 *   Observer invoked with each derived reveal document.
 * @property {(result: VerifyDisclosureResult) => void} [onVerify] - Observer
 *   invoked with each verify_disclosure result (the authoritative verdict).
 */

/**
 * Build the SD tool set bound to a wallet.
 *
 * @param {BuildSdToolsOptions} options - The wallet and optional observers.
 * @returns {Record<string, unknown>} The tool set keyed by tool name.
 */
export function buildSdTools(options) {
  const {wallet, onDisclosure, onVerify} = options;
  return {
    request_disclosure: tool({
      description:
        'Ask the holder\'s wallet to derive a reveal document disclosing ' +
        'only the named claims (e.g. age_over_21). The full credential never ' +
        'leaves the wallet.',
      inputSchema: z.object({claims: z.array(z.string())}),
      execute: async ({claims}) => {
        const reveal = await wallet.requestDisclosure(claims);
        if(onDisclosure) {
          onDisclosure(reveal);
        }
        return reveal;
      }
    }),
    verify_disclosure: tool({
      description:
        'Verify a reveal document\'s derived ecdsa-sd-2023 proof. This is ' +
        'the authoritative decision.',
      inputSchema: z.object({
        revealDocument: z.record(z.string(), z.unknown())
      }),
      execute: async ({revealDocument}) => {
        const result = await verifyDisclosureTool(
          /** @type {any} */ ({revealDocument})
        );
        if(onVerify) {
          onVerify(result);
        }
        return result;
      }
    })
  };
}
