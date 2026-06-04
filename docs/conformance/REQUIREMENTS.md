<!--
Copyright (c) 2026 Digital Bazaar, Inc.
-->
# KYA-OS L1 / L2 Conformance Requirements

This is the requirement register for `agent-credential-server` as Digital
Bazaar's reference implementation of **KYA-OS** (Know Your Agent OS; DIF Trusted
AI Agents WG) Levels **L1** and **L2**. **MCP-I** is the MCP binding.

Each requirement has a stable ID (`R-L1-n`, `R-L2-n`, `R-X-n` for
cross-cutting). The spec-citation comments in source and the conformance map
(`CONFORMANCE.md`, forthcoming) reference these IDs. Keywords MUST / SHOULD /
MAY follow RFC 2119.

> **Sourcing note.** KYA-OS does not yet publish numbered normative clauses, so
> these requirements are derived from the KYA-OS conformance-level descriptions
> and primitives (see Sources) and from this repo's `SPEC.md §2`. Wording is
> ours; it traces to the level/primitive it implements, not to an official
> clause number. Re-anchor to clause numbers if/when the spec publishes them.

**Sources:**
- KYA-OS overview — https://blog.identity.foundation/kya-os/
- MCP-I binding FAQ —
  https://modelcontextprotocol-identity.io/docs/getting-started/faq
- This repo: `SPEC.md §2` (KYA-OS background), `§5` (spec-traceability)

**Conformance levels (scope of this register):**
- **L1 (Agent).** Agent has a stable DID. Delegation optional.
- **L2 (Agent + User).** Both have DIDs; the user issues a VC to the agent.
  Per-request edge verification enforces revocation, expiry, and scoped access.
- **L3 (Agent + User + Service).** Selective disclosure, token bridging, audit
  trails — **out of scope here** (Phase 2).

---

## L1 — Agent identity

| ID | Kw | Requirement | Enforced in | Proven by |
|----|----|-------------|-------------|-----------|
| **R-L1-1** | MUST | An agent is identified by a DID. | `lib/tools/auth.js`, `lib/core/challenge.js` | `challenge.test.js` |
| **R-L1-2** | MUST | `did:key` agent DIDs resolve offline (deterministic, no network). | `lib/tools/didKeyContext.js` (`resolveAgentKey`) | `resolveAgentKey.test.js` |
| **R-L1-3** | MUST | Non-`did:key` DIDs resolve via a method-appropriate resolver; `did:web` natively, else Universal Resolver. | `lib/core/resolver.js`, `lib/core/didWeb.js` | `resolver.test.js`, `didWeb.test.js` |
| **R-L1-4** | SHOULD | `did:web` resolution falls back to the Universal Resolver when the direct fetch fails. | `lib/core/resolver.js` | `resolver.test.js` |
| **R-L1-5** | MUST | An agent authenticates control of its DID via a signed nonce challenge (no key material transmitted). | `lib/core/challenge.js`, `lib/tools/auth.js` | `challenge.test.js`, `delegate.test.js` (authProof) |
| **R-L1-6** | MUST | An expired or wrongly-signed agent challenge is rejected. | `lib/core/challenge.js` (`isChallengeExpired`), `lib/tools/delegate.js` step 0 | `delegate.test.js` (authProof) |

## L2 — User-to-agent delegation (per-request edge verification)

The `check_delegation` pipeline (`lib/tools/delegate.js`) is the L2 enforcement
core. Its numbered steps map 1:1 to the requirements below and fail closed.

| ID | Kw | Requirement | Enforced in | Proven by |
|----|----|-------------|-------------|-----------|
| **R-L2-1** | MUST | A delegation is a Verifiable Credential the user issues to the agent. | `lib/core/vc.js` (`issueCredentialDI`), `lib/tools/issue.js` | `vcDataIntegrity.test.js` |
| **R-L2-2** | MUST | The credential is bound to the requesting agent: `credentialSubject.id` MUST equal the agent DID. | `lib/tools/delegate.js` step 1 | `delegate.test.js` (subject mismatch) |
| **R-L2-3** | MUST | The credential's cryptographic proof MUST verify (eddsa-rdfc-2022 Data Integrity). | `lib/core/vc.js` (`verifyCredentialDI`) | `vcDataIntegrity.test.js` (tampered, wrong key) |
| **R-L2-4** | MUST | The proof MUST verify against the issuer DID resolved from the credential. | `lib/core/vc.js` + document loader | `vcDataIntegrity.test.js`, `delegate.test.js` (issuer swap) |
| **R-L2-5** | MUST | An expired credential (`validUntil` past, beyond clock skew) MUST be denied. | `lib/core/vc.js`, `lib/tools/delegate.js` step 2 | `vcDataIntegrity.test.js`, `delegate.test.js` (expired) |
| **R-L2-6** | MUST | A not-yet-valid credential (`validFrom` in the future) MUST be denied. | `lib/core/vc.js`, `lib/tools/delegate.js` step 2 | `vcDataIntegrity.test.js`, `delegate.test.js` (not yet valid) |
| **R-L2-7** | MUST | When `credentialStatus` is present, revocation MUST be checked per request; a revoked credential is denied. | `lib/tools/delegate.js` step 3, `lib/core/revocation.js`, `lib/core/statusListFetcher.js` | `revocation.test.js`, `delegate.test.js` |
| **R-L2-8** | MUST | Revocation uses StatusList2021 semantics compatible with DB `@digitalbazaar/vc-status-list` (base64url+gzip, MSB-first). | `lib/core/revocation.js` | `revocation.test.js` |
| **R-L2-9** | MUST | Authorization is scoped: the requested action MUST satisfy the credential's permitted claims/scope. | `lib/core/claimPredicates.js`, `lib/tools/delegate.js` step 4 | `claimPredicates.test.js`, `delegate.test.js` |
| **R-L2-10** | MUST | Scope predicates MUST NOT coerce types: a string `"25"` or boolean MUST NOT satisfy a numeric predicate. | `lib/core/claimPredicates.js` (`evaluatePredicate`) | `claimPredicates.test.js` (type confusion) |
| **R-L2-11** | MUST | Multi-hop delegation chains MUST verify cryptographically from a root capability to the leaf agent (zcap). | `lib/tools/verifyChain.js`, `lib/core/zcapChain.js` | `verifyChain.test.js` |
| **R-L2-12** | MUST | A delegation chain MUST enforce expiry attenuation (a child MUST NOT outlive its parent) and reject scope/target mismatch. | `lib/tools/verifyChain.js`, `@digitalbazaar/zcap` | `verifyChain.test.js` (extended expiry, root mismatch) |

## Cross-cutting (apply to L1 and L2)

| ID | Kw | Requirement | Enforced in | Proven by |
|----|----|-------------|-------------|-----------|
| **R-X-1** | MUST | Authorization decisions are made by tested pure code, never by an LLM; the model only relays `check_delegation`'s structured result. | `demo-agent/lib/agent.js` (`runAgent`) | `demo-agent/lib/__tests__/agent.test.js` (eval gate, tool-deference) |
| **R-X-2** | MUST | No key material or secret appears in agent output or tool-call arguments. | `demo-agent/lib/agent.js` | `agent.test.js`, `scenarios.test.js` (leakage canary) |
| **R-X-3** | MUST | The JSON-LD document loader resolves `@context` without network IO on the hot path (cached, bundled contexts, offline did:key). | `lib/core/documentLoader.js` | `documentLoader.test.js` |
| **R-X-4** | SHOULD | Expected failures return structured result objects (`{authorized/valid: false, reason}`), not thrown exceptions. | `lib/tools/*`, `lib/core/*` | all tool/core tests |

## L3 — Selective disclosure (Phase 2, `ecdsa-sd-2023`)

Age is modeled the ISO/IEC 18013-5 way: the issuer precomputes `age_over_NN`
boolean flags from the DOB, and the holder selectively discloses only the
needed flag — never the birthdate. See `docs/phase-2-spec.md`.

| ID | Kw | Requirement | Enforced in | Proven by |
|----|----|-------------|-------------|-----------|
| **R-L3-1** | MUST | A holder can derive a presentation revealing a subset of claims, hiding the rest. | `lib/core/vcSd.js` (`deriveDisclosure`), `lib/tools/deriveDisclosure.js` | `vcSd.test.js`, `sdTools.test.js` |
| **R-L3-2** | MUST | A derived presentation verifies only if the revealed claims were in the issuer's original signature. | `lib/core/vcSd.js` (`verifyDisclosure`) | `vcSd.test.js` (tampered), `sdTools.test.js` |
| **R-L3-3** | MUST | Mandatory claims (issuer, validity) are always present in a reveal document; substantive personal data (DOB, name) is never mandatory. | `lib/tools/issueSd.js` (`DEFAULT_MANDATORY_POINTERS`) | `sdTools.test.js` |
| **R-L3-6** | MUST | A disclosure request for more than two `age_over_NN` flags is rejected (ISO 18013-5 reader limit). | `lib/tools/deriveDisclosure.js` | `sdTools.test.js` (R-L3-6) |

Demo (Phase 2, the selective-disclosure demo):

| ID | Kw | Requirement | Enforced in | Proven by |
|----|----|-------------|-------------|-----------|
| **R-L3-4** | SHOULD | Document that `ecdsa-sd-2023` presentations are linkable (unlinkability → bbs-2023). | `docs/phase-2-spec.md` §2/§6, `README.md` | n/a (documentation) |
| **R-L3-5** | MUST | The birthdate and other hidden fields never enter agent-side code, output, or tool-call arguments (the wallet seam). | `demo-agent/lib/wallet.js` (closure-held credential), `demo-agent/lib/sdTools.js` | `wallet.test.js`, `sdEval.test.js` (leakage canary) |

## Deliberately out of scope (later than Phase 2)

| ID | Requirement | Why deferred |
|----|-------------|--------------|
| R-L3-7 | Unlinkable presentations (a verifier cannot correlate two derivations). | Needs `bbs-2023` (BLS12-381 keys). Phase 2.5. |
| R-L3-8 | Credential-to-token bridging + audit trails. | L3 service-side concern. |

---

*This register is the anchor for the forthcoming `CONFORMANCE.md` (MUST→test
matrix) and the `// KYA-OS R-Lx-n` spec-citation comments at each enforcement
point. Keep IDs stable; append, do not renumber.*
