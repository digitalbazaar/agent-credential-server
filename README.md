> **WIP — will change substantially.**

# agent-credential-server

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
│ issues a VC 2.0 credential (Data Integrity proof, Ed25519)
▼
Agent (Claude with tool use)
│ calls MCP tools
▼
MCP Server
├── resolve_did → DID Document (Universal Resolver)
├── verify_credential → {valid, issuer, subject, claims}
├── issue_credential → signed VC 2.0 credential object
├── check_delegation → {authorized, reason}
└── verify_delegation_chain → zcap capability-chain verification
```

Two npm workspace packages:
- `mcp-server/` - MCP server exposing DID/VC tools
- `demo-agent/` - Claude-powered CLI demo of age-gated access control

Within `mcp-server/lib/`, pure side-effect-free logic lives in `core/`
(`crypto`, `vc`, `documentLoader`, `zcapChain`, `claimPredicates`,
`revocation`, `challenge`, `resolver`) and IO orchestration lives in `tools/`
(the MCP tool handlers). Tools compose core functions as a thin imperative
shell.

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
| `verify_credential` | `credential` (VC 2.0 object) | `{valid, issuer, subject, claims, reason?}` |
| `issue_credential` | `subjectDid, claims, privateKeyBase64url, expiresInSeconds?, delegatedFrom?` | signed VC 2.0 object (issuer `did:key` derived from the key) |
| `check_delegation` | `agentDid, requestedAction, credential, requiredClaims?, authProof?` | `{authorized, reason}` |
| `create_challenge` | `agentDid, ttlSeconds?` | `{nonce, issuedAt, expiresAt, agentDid}` |
| `verify_auth` | `agentDid, nonce, issuedAt, signatureBase64url, expiresAt?` | `{authenticated, reason}` |
| `verify_delegation_chain` | `rootCapability, delegatedCapability, agentDid, expectedAction, expectedTarget` | `{authorized, reason}` |

## Demo Scenario

A human issues a short-lived age-verification credential to an agent:

```json
{ "age_verified": true, "over_21": true }
```

1. The human's DID signs a VC asserting the agent's age claims
2. The agent presents the VC when requesting age-restricted access
3. The MCP server verifies the credential and checks the required claims
4. Access granted or denied - with a reason, tied to a signed credential

The demo agent is **model-agnostic** (built on the Vercel AI SDK) and never
decides access itself: it calls the `check_delegation` tool and reports that
tool's verdict. Pick a provider with `AGENT_PROVIDER` or `--provider` (default
`anthropic`; `ollama` runs locally with no API key).

```bash
npm run start --workspace=demo-agent -- valid     # valid VC → granted
npm run start --workspace=demo-agent -- tampered  # modified VC → denied
npm run start --workspace=demo-agent -- expired   # past TTL → denied
npm run start --workspace=demo-agent -- authn     # challenge-response auth
npm run start --workspace=demo-agent -- valid --provider=ollama
```

The agent's behaviour is guarded by a deterministic, offline **eval** (a golden
dataset plus tool-deference and leakage canaries) that runs in CI on every push.

## Stack

- JavaScript (ESM) + JSDoc types / Node - **not** TypeScript (DB house style)
- `@modelcontextprotocol/sdk` - MCP server
- `@digitalbazaar/vc` + `@digitalbazaar/data-integrity` + `eddsa-rdfc-2022` -
  VC 2.0 credentials with Data Integrity proofs
- `@digitalbazaar/ed25519-multikey` + `@digitalbazaar/did-method-key` - keys
  and `did:key` resolution
- `@digitalbazaar/zcap` - authorization-capability delegation chains
- Universal Resolver - chain-agnostic DID resolution (fallback)
- Vercel AI SDK (`ai` + `@ai-sdk/anthropic`, `ollama-ai-provider-v2`) -
  model-agnostic demo agent

## References

- [W3C DID Core](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials 2.0](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C Data Integrity](https://www.w3.org/TR/vc-data-integrity/)
- [Authorization Capabilities (zcap)](https://w3c-ccg.github.io/zcap-spec/)
- [Universal Resolver](https://dev.uniresolver.io)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
