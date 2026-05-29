> **WIP — will change substantially.**

# did-resolver-agent

**Agent authorization without a central authority.**

AI agents are taking on real work - deploying code, calling APIs, managing files.
But most authorization today is session-based, centralized, or just implicit. When
something goes wrong, "the AI did it" is not an audit trail.

This project uses [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
and [Verifiable Credentials (VCs)](https://www.w3.org/TR/vc-data-model/) as the
authorization layer for agentic systems. A human issues a signed, scoped credential
to an agent. Any verifier checks it against the DID document - no central registry,
no round-trip to an auth server, no shared secret.

Implemented as an [MCP server](https://github.com/modelcontextprotocol/typescript-sdk)
so any Claude-powered agent can use it today.

---

## Why DIDs + VCs instead of OAuth?

OAuth requires a central auth server both parties trust and can reach. That assumption
breaks down in multi-agent systems, offline environments, and cross-provider workflows.

| | OAuth | DID + VC |
|---|---|---|
| Central authority required | ✓ | ✗ |
| Works offline / across systems | ✗ | ✓ |
| Credentials travel with the agent | ✗ | ✓ |
| Composable delegation to sub-agents | ✗ | ✓ |
| Cryptographic audit trail | ✗ | ✓ |

See [USE_CASES.md](./USE_CASES.md) for real-world scenarios.

---

## Architecture

```text
Human
│ issues VC (signed with human's DID key)
▼
Agent (Claude with tool use)
│ calls MCP tools
▼
MCP Server
├── resolve_did → DID Document (Universal Resolver)
├── verify_credential → {valid, issuer, subject, claims, expiry}
├── issue_credential → signed VC (JWT, Ed25519)
└── check_delegation → {authorized, reason}
```

Two npm workspace packages:
- `mcp-server/` - MCP server exposing DID/VC tools
- `demo-agent/` - Claude-powered CLI demo of deployment authorization

---

## Quick Start

```bash
npm install
npm test                                          # run tests
npm run typecheck                                 # type check
npm run dev --workspace=mcp-server                # start MCP server
npm run start --workspace=demo-agent -- valid     # valid VC → authorized
npm run start --workspace=demo-agent -- tampered  # modified payload → denied
npm run start --workspace=demo-agent -- expired   # past TTL → denied
```

## MCP Tools

| Tool | Input | Output |
|------|-------|--------|
| `resolve_did` | `did: string` | DID Document JSON |
| `verify_credential` | `vcJwt: string` | `{valid, issuer, subject, claims, expires}` |
| `issue_credential` | `subjectDid, claims, issuerDid, privateKeyBase64url, expiresInSeconds?, audience?, delegatedFrom?` | `{jwt}` |
| `check_delegation` | `agentDid, requestedAction, vcJwt, requiredClaims?, expectedAudience?, authProof?` | `{authorized, reason}` |
| `create_challenge` | `agentDid, ttlSeconds?` | `{nonce, issuedAt, expiresAt, agentDid}` |
| `verify_auth` | `agentDid, nonce, issuedAt, signatureBase64url, expiresAt?` | `{authenticated, reason}` |
| `verify_delegation_chain` | `vcChain: string[], agentDid` | `{authorized, depth, reason, chain?}` |

## Demo Scenario

An engineer issues a short-lived deployment credential to a CI agent:

```json
{ "environment": "staging", "approved_by": "did:key:z6MkEngineer", "max_replicas": 3 }
```

1. Engineer's DID signs a VC granting deploy access to staging
2. Agent presents the VC when attempting a deployment action
3. MCP server resolves the engineer's DID, verifies the signature, checks claims
4. Access granted or denied - with a reason, tied to a signed credential

Test cases cover the full failure surface: valid credential, tampered payload
(signature mismatch), and expired TTL.

## Stack

- JavaScript (ESM) + JSDoc types / Node - **not** TypeScript (DB house style)
- `@modelcontextprotocol/sdk` - MCP server
- `@noble/ed25519` + `@noble/hashes` - Ed25519 signing
- Universal Resolver - chain-agnostic DID resolution
- `@anthropic-ai/sdk` - demo agent

## References

- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/)
- [Universal Resolver](https://dev.uniresolver.io)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
