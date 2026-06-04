/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {McpServer} from '@modelcontextprotocol/sdk/server/mcp.js';
import {StdioServerTransport} from '@modelcontextprotocol/sdk/server/stdio.js';
import {z} from 'zod';

import {createChallengeTool, verifyAuthTool} from './tools/auth.js';
import {checkDelegation} from './tools/delegate.js';
import {deriveDisclosureTool} from './tools/deriveDisclosure.js';
import {issueCredentialTool} from './tools/issue.js';
import {issueSdCredentialTool} from './tools/issueSd.js';
import {resolveDIDTool} from './tools/resolve.js';
import {verifyCredentialTool} from './tools/verify.js';
import {verifyDelegationChainTool} from './tools/verifyChain.js';
import {verifyDisclosureTool} from './tools/verifyDisclosure.js';

/**
 * @typedef {import('./tools/verifyDisclosure.js').VerifyDisclosureToolInput}
 *   VerifyDisclosureToolInput
 */

process.on('unhandledRejection', reason => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1);
});

const server = new McpServer({
  name: 'agent-credential-server', version: '0.1.0'
});

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
      'Verify an authorization-capability (zcap) delegation chain from a ' +
      'root capability down to an agent',
    inputSchema: {
      rootCapability: z.record(z.string(), z.unknown())
        .describe('The root capability the chain must descend from'),
      delegatedCapability: z.record(z.string(), z.unknown())
        .describe('The leaf delegated capability presented by the agent'),
      agentDid: z.string().describe('The expected leaf agent DID'),
      expectedAction: z.string()
        .describe('The action the chain must allow'),
      expectedTarget: z.string()
        .describe('The invocation target (protected resource) URL')
    }
  },
  async input => {
    const result = await verifyDelegationChainTool(
      /** @type {import("./tools/verifyChain.js").VerifyChainInput} */ (input)
    );
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

server.registerTool(
  'issue_sd_credential',
  {
    description:
      'Issue a VC 2.0 selective-disclosure credential (ecdsa-sd-2023, ' +
      'P-256). The issuer did:key is derived from the signing key. Claims ' +
      'should include precomputed age_over_NN flags.',
    inputSchema: {
      subjectDid: z.string(),
      claims: z.record(z.string(), z.unknown())
        .describe('Claims to embed, including age_over_NN flags'),
      publicKeyMultibase: z.string()
        .describe('Issuer P-256 public-key multibase'),
      privateKeyMultibase: z.string()
        .describe('Issuer P-256 secret-key multibase; issuer DID is derived'),
      mandatoryPointers: z.array(z.string()).optional()
        .describe('JSON pointers always revealed (default: issuer + validity)'),
      expiresInSeconds: z.number().optional()
        .describe('Optional TTL in seconds')
    }
  },
  async input => {
    const result = await issueSdCredentialTool(
      /** @type {import("./tools/issueSd.js").IssueSdInput} */ (input)
    );
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

server.registerTool(
  'derive_disclosure',
  {
    description:
      'Derive a reveal document from a base SD credential, disclosing only ' +
      'the requested claims. At most two age_over_NN flags per request.',
    inputSchema: {
      credential: z.record(z.string(), z.unknown())
        .describe('The base SD credential (with an ecdsa-sd-2023 proof)'),
      revealClaims: z.array(z.string())
        .describe('credentialSubject claim names to disclose')
    }
  },
  async input => {
    const result = await deriveDisclosureTool(
      /** @type {import("./tools/deriveDisclosure.js").DeriveDisclosureInput} */
      (input)
    );
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

server.registerTool(
  'verify_disclosure',
  {
    description:
      'Verify a reveal document\'s derived ecdsa-sd-2023 proof and return ' +
      'the revealed claims',
    inputSchema: {
      revealDocument: z.record(z.string(), z.unknown())
        .describe('The reveal document to verify')
    }
  },
  async input => {
    const result = await verifyDisclosureTool(
      /** @type {VerifyDisclosureToolInput} */ (input)
    );
    return {content: [{type: 'text', text: JSON.stringify(result, null, 2)}]};
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
