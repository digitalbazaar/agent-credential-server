/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Claude-powered demo agent.
 * Uses MCP tools (via in-process call) to enforce credential-based access.
 */
import {
  createChallengeTool, verifyAuthTool
} from '../../mcp-server/lib/tools/auth.js';
import Anthropic from '@anthropic-ai/sdk';
import {checkDelegation} from '../../mcp-server/lib/tools/delegate.js';
import {issueCredentialTool} from '../../mcp-server/lib/tools/issue.js';
import {resolveDIDTool} from '../../mcp-server/lib/tools/resolve.js';
import {verifyCredentialTool} from '../../mcp-server/lib/tools/verify.js';
import {
  verifyDelegationChainTool
} from '../../mcp-server/lib/tools/verifyChain.js';

process.on('unhandledRejection', reason => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1);
});

const client = new Anthropic();

/** @type {Anthropic.Tool[]} */
const TOOLS = [
  {
    name: 'resolve_did',
    description: 'Fetch a DID Document via the Universal Resolver',
    input_schema: {
      type: 'object',
      properties: {
        did: {type: 'string', description: 'The DID to resolve'}
      },
      required: ['did']
    }
  },
  {
    name: 'verify_credential',
    description:
      'Verify a JWT-format Verifiable Credential against the issuer DID',
    input_schema: {
      type: 'object',
      properties: {
        vcJwt: {type: 'string', description: 'The JWT-encoded VC'}
      },
      required: ['vcJwt']
    }
  },
  {
    name: 'issue_credential',
    description: 'Issue a signed JWT Verifiable Credential (Ed25519)',
    input_schema: {
      type: 'object',
      properties: {
        subjectDid: {type: 'string'},
        claims: {type: 'object'},
        issuerDid: {type: 'string'},
        privateKeyBase64url: {type: 'string'},
        expiresInSeconds: {type: 'number'},
        audience: {type: 'string'},
        delegatedFrom: {type: 'string'}
      },
      required: ['subjectDid', 'claims', 'issuerDid', 'privateKeyBase64url']
    }
  },
  {
    name: 'check_delegation',
    description: 'Verify that an agent\'s VC authorizes a specific action',
    input_schema: {
      type: 'object',
      properties: {
        agentDid: {type: 'string'},
        requestedAction: {type: 'string'},
        vcJwt: {type: 'string'},
        requiredClaims: {type: 'object'},
        expectedAudience: {type: 'string'},
        authProof: {
          type: 'object',
          properties: {
            nonce: {type: 'string'},
            issuedAt: {type: 'number'},
            expiresAt: {type: 'number'},
            signatureBase64url: {type: 'string'}
          }
        }
      },
      required: ['agentDid', 'requestedAction', 'vcJwt']
    }
  },
  {
    name: 'create_challenge',
    description: 'Generate an authentication challenge for an agent to sign',
    input_schema: {
      type: 'object',
      properties: {
        agentDid: {type: 'string'},
        ttlSeconds: {type: 'number'}
      },
      required: ['agentDid']
    }
  },
  {
    name: 'verify_auth',
    description: 'Verify an agent\'s signed challenge response',
    input_schema: {
      type: 'object',
      properties: {
        agentDid: {type: 'string'},
        nonce: {type: 'string'},
        issuedAt: {type: 'number'},
        signatureBase64url: {type: 'string'},
        expiresAt: {type: 'number'}
      },
      required: ['agentDid', 'nonce', 'issuedAt', 'signatureBase64url']
    }
  },
  {
    name: 'verify_delegation_chain',
    description:
      'Verify a chain of delegation VCs from a root issuer down to an agent',
    input_schema: {
      type: 'object',
      properties: {
        vcChain: {type: 'array', items: {type: 'string'}},
        agentDid: {type: 'string'}
      },
      required: ['vcChain', 'agentDid']
    }
  }
];

/**
 * Dispatch a named MCP tool call to its in-process handler.
 *
 * @param {string} name - The tool name to invoke.
 * @param {Record<string, unknown>} input - The tool input arguments.
 * @returns {Promise<unknown>} The tool result.
 */
async function callTool(name, input) {
  switch(name) {
    case 'resolve_did':
      return resolveDIDTool(/** @type {string} */ (input.did));
    case 'verify_credential':
      return verifyCredentialTool(/** @type {string} */ (input.vcJwt));
    case 'issue_credential':
      return issueCredentialTool(/** @type {any} */ (input));
    case 'check_delegation':
      return checkDelegation(/** @type {any} */ (input));
    case 'create_challenge':
      return createChallengeTool(/** @type {any} */ (input));
    case 'verify_auth':
      return verifyAuthTool(/** @type {any} */ (input));
    case 'verify_delegation_chain':
      return verifyDelegationChainTool(/** @type {any} */ (input));
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

/**
 * Run the demo agent loop against the given user prompt.
 *
 * @param {string} userPrompt - The prompt describing the access scenario.
 * @returns {Promise<void>} Resolves when the agent finishes its turn.
 */
export async function runAgent(userPrompt) {
  console.log('\n─── Agent starting ───');
  console.log('User:', userPrompt);

  /** @type {Anthropic.MessageParam[]} */
  const messages = [{role: 'user', content: userPrompt}];

  while(true) {
    const response = await client.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 4096,
      tools: TOOLS,
      messages
    });

    // Add assistant response to history
    messages.push({role: 'assistant', content: response.content});

    if(response.stop_reason === 'end_turn') {
      // Extract final text
      for(const block of response.content) {
        if(block.type === 'text') {
          console.log('\nAgent:', block.text);
        }
      }
      break;
    }

    if(response.stop_reason === 'tool_use') {
      /** @type {Anthropic.ToolResultBlockParam[]} */
      const toolResults = [];

      for(const block of response.content) {
        if(block.type === 'tool_use') {
          console.log(`\n  → Calling tool: ${block.name}`);
          const result = await callTool(
            block.name,
            /** @type {Record<string, unknown>} */ (block.input)
          );
          const resultText = JSON.stringify(result, null, 2);
          const truncated = resultText.length > 200 ? '...' : '';
          console.log(`  ← Result: ${resultText.slice(0, 200)}${truncated}`);

          toolResults.push({
            type: 'tool_result',
            tool_use_id: block.id,
            content: resultText
          });
        }
      }

      messages.push({role: 'user', content: toolResults});
    }
  }

  console.log('─── Agent done ───\n');
}
