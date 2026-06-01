/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {z} from 'zod';

import {createChallengeTool, verifyAuthTool} from './tools/auth.js';
import {checkDelegation} from './tools/delegate.js';
import {issueCredentialTool} from './tools/issue.js';
import {resolveDIDTool} from './tools/resolve.js';
import {verifyCredentialTool} from './tools/verify.js';
import {verifyDelegationChainTool} from './tools/verifyChain.js';

process.on('unhandledRejection', reason => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1);
});

const server = new McpServer({name: 'did-resolver-agent', version: '0.1.0'});

server.registerTool(
  'resolve_did',
  {
    description: 'Fetch a DID Document via the Universal Resolver',
    inputSchema: {
      did: z.string()
        .describe('The DID to resolve, e.g. did:web:example.com')
    }
  },
  async ({did}) => {
    const result = await resolveDIDTool(did);
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

server.registerTool(
  'verify_credential',
  {
    description:
      'Verify a VC 2.0 Data Integrity credential against the issuer DID',
    inputSchema: {
      credential: z.record(z.string(), z.unknown())
        .describe('The VC 2.0 credential object (with proof)')
    }
  },
  async ({credential}) => {
    const result = await verifyCredentialTool(
      /** @type {import("./tools/verify.js").DataIntegrityCredential} */ (
        credential
      )
    );
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

server.registerTool(
  'issue_credential',
  {
    description:
      'Issue a VC 2.0 Data Integrity credential (Ed25519, eddsa-rdfc-2022). ' +
      'The issuer did:key is derived from the signing key.',
    inputSchema: {
      subjectDid: z.string(),
      claims: z.record(z.string(), z.unknown())
        .describe('Claims to embed in the VC'),
      privateKeyBase64url: z.string()
        .describe('Base64url Ed25519 seed (32 bytes); issuer DID is derived'),
      expiresInSeconds: z.number().optional()
        .describe('Optional TTL in seconds'),
      delegatedFrom: z.string().optional()
        .describe('Optional parent VC reference for delegation chains')
    }
  },
  async input => {
    const result = await issueCredentialTool(input);
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

server.registerTool(
  'check_delegation',
  {
    description: 'Verify that an agent\'s VC authorizes a specific action',
    inputSchema: {
      agentDid: z.string(),
      requestedAction: z.string(),
      credential: z.record(z.string(), z.unknown())
        .describe('The VC 2.0 credential object (with proof)'),
      requiredClaims: z.record(z.string(), z.unknown()).optional()
        .describe(
          'Key/value pairs or predicate objects that must be present in ' +
          'the VC claims'
        ),
      authProof: z.object({
        nonce: z.string(),
        issuedAt: z.number(),
        expiresAt: z.number(),
        signatureBase64url: z.string()
      }).optional()
        .describe('Agent authentication proof from create_challenge')
    }
  },
  async input => {
    const result = await checkDelegation(
      /** @type {import("./tools/delegate.js").CheckDelegationInput} */ (input)
    );
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

server.registerTool(
  'create_challenge',
  {
    description: 'Generate an authentication challenge for an agent to sign',
    inputSchema: {
      agentDid: z.string(),
      ttlSeconds: z.number().optional()
        .describe('Challenge TTL in seconds (default 300)')
    }
  },
  async input => {
    const result = await createChallengeTool(input);
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

server.registerTool(
  'verify_auth',
  {
    description:
      'Verify an agent\'s signed challenge response (authenticate the agent)',
    inputSchema: {
      agentDid: z.string(),
      nonce: z.string(),
      issuedAt: z.number(),
      signatureBase64url: z.string(),
      expiresAt: z.number().optional()
    }
  },
  async input => {
    const result = await verifyAuthTool(input);
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

server.registerTool(
  'verify_delegation_chain',
  {
    description:
      'Verify a chain of delegation VCs from a root issuer down to an agent',
    inputSchema: {
      vcChain: z.array(z.string())
        .describe('Array of JWT VCs from root to leaf'),
      agentDid: z.string().describe('The expected leaf agent DID')
    }
  },
  async input => {
    const result = await verifyDelegationChainTool(input);
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
