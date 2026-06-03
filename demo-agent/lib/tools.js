/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The MCP tool set, exposed to the model as Vercel AI SDK tools. Each tool
 * delegates to the genuine, tested mcp-server handler — the model orchestrates
 * them but is never the authority on a decision. check_delegation is the
 * security boundary; its result is returned verbatim.
 */
import {checkDelegation} from 'mcp-server/lib/tools/delegate.js';
import {
  createChallengeTool, verifyAuthTool
} from 'mcp-server/lib/tools/auth.js';
import {resolveDIDTool} from 'mcp-server/lib/tools/resolve.js';
import {tool} from 'ai';
import {verifyCredentialTool} from 'mcp-server/lib/tools/verify.js';
import {z} from 'zod';

/**
 * @typedef {object} BuildToolsOptions
 * @property {(result: {authorized: boolean, reason: string}) => void}
 *   [onCheckDelegation] - Observer invoked with each check_delegation result
 *   (used by the eval to capture the authoritative decision).
 */

/**
 * Build the AI-SDK tool set wired to the in-process mcp-server handlers.
 *
 * @param {BuildToolsOptions} options - Optional observers.
 * @returns {Record<string, unknown>} The tool set keyed by tool name.
 */
export function buildTools(options = {}) {
  return {
    resolve_did: tool({
      description: 'Fetch a DID Document via the Universal Resolver.',
      inputSchema: z.object({did: z.string()}),
      execute: async ({did}) => resolveDIDTool(did)
    }),
    verify_credential: tool({
      description:
        'Verify a VC 2.0 Data Integrity credential against its issuer DID.',
      inputSchema: z.object({
        credential: z.record(z.string(), z.unknown())
      }),
      execute: async ({credential}) =>
        verifyCredentialTool(/** @type {any} */ (credential))
    }),
    check_delegation: tool({
      description:
        'Decide whether an agent\'s credential authorizes a requested ' +
        'action. This is the authoritative access decision.',
      inputSchema: z.object({
        agentDid: z.string(),
        requestedAction: z.string(),
        credential: z.record(z.string(), z.unknown()),
        requiredClaims: z.record(z.string(), z.unknown()).optional(),
        authProof: z.object({
          nonce: z.string(),
          issuedAt: z.number(),
          expiresAt: z.number(),
          signatureBase64url: z.string()
        }).optional()
      }),
      execute: async input => {
        const result = await checkDelegation(/** @type {any} */ (input));
        if(options.onCheckDelegation) {
          options.onCheckDelegation(result);
        }
        return result;
      }
    }),
    create_challenge: tool({
      description: 'Generate an authentication challenge for an agent to sign.',
      inputSchema: z.object({
        agentDid: z.string(),
        ttlSeconds: z.number().optional()
      }),
      execute: async input => createChallengeTool(input)
    }),
    verify_auth: tool({
      description: 'Verify an agent\'s signed challenge response.',
      inputSchema: z.object({
        agentDid: z.string(),
        nonce: z.string(),
        issuedAt: z.number(),
        signatureBase64url: z.string(),
        expiresAt: z.number().optional()
      }),
      execute: async input => verifyAuthTool(input)
    })
  };
}
