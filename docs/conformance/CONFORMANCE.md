<!--
Copyright (c) 2026 Digital Bazaar, Inc.
-->
# Conformance Map (Requirement → Test)

This map proves each requirement in [`REQUIREMENTS.md`](./REQUIREMENTS.md) is
covered by an automated test. Every row cites the requirement ID, the test
file, and the exact `it(...)` titles that exercise it. All listed tests run in
CI (`npm test`).

Test paths are relative to the workspace root:
- `mcp-server/lib/__tests__/…`
- `demo-agent/lib/__tests__/…`

> Keep this map in sync when adding requirements or renaming tests. A
> requirement with no proving test is a conformance gap, not a passing row.

---

## L1 — Agent identity

| Req | Test file | Proving test(s) |
|-----|-----------|-----------------|
| **R-L1-1** | `mcp-server/.../challenge.test.js` | `creates a token with the given agentDid` |
| **R-L1-2** | `mcp-server/.../resolveAgentKey.test.js` | `resolves a did:key offline without the network resolver` |
| **R-L1-3** | `mcp-server/.../resolver.test.js`, `didWeb.test.js` | `resolves did:web by fetching .well-known/did.json directly`; `resolves a non-web DID via the Universal Resolver`; `maps a bare domain to its .well-known URL` |
| **R-L1-4** | `mcp-server/.../resolver.test.js` | `falls back to the Universal Resolver when did:web fetch is non-2xx`; `falls back to the Universal Resolver when did:web fetch throws` |
| **R-L1-5** | `mcp-server/.../challenge.test.js`, `delegate.test.js` | `returns valid for correct signature within TTL`; `authorizes when authProof is valid` |
| **R-L1-6** | `mcp-server/.../challenge.test.js`, `delegate.test.js` | `returns invalid for expired token`; `returns invalid for wrong key`; `denies when authProof challenge is expired`; `denies when authProof signature is wrong` |

## L2 — User-to-agent delegation (per-request edge verification)

| Req | Test file | Proving test(s) |
|-----|-----------|-----------------|
| **R-L2-1** | `mcp-server/.../vcDataIntegrity.test.js` | `issues a VC 2.0 with an eddsa-rdfc-2022 proof` |
| **R-L2-2** | `mcp-server/.../delegate.test.js` | `denies when VC subject does not match agent DID` |
| **R-L2-3** | `mcp-server/.../vcDataIntegrity.test.js` | `rejects a tampered credentialSubject`; `verifies a freshly issued credential` |
| **R-L2-4** | `mcp-server/.../vcDataIntegrity.test.js`, `delegate.test.js` | `rejects a credential signed by a different key`; `denies when the issuer is swapped to an unrelated DID` |
| **R-L2-5** | `mcp-server/.../vcDataIntegrity.test.js`, `delegate.test.js` | `rejects an expired credential`; `denies when VC is expired` |
| **R-L2-6** | `mcp-server/.../vcDataIntegrity.test.js`, `delegate.test.js` | `rejects a not-yet-valid credential`; `denies when VC is not yet valid` |
| **R-L2-7** | `mcp-server/.../revocation.test.js` | `returns revoked when bit set`; `returns not revoked when bit clear` |
| **R-L2-8** | `mcp-server/.../revocation.test.js` | `decodes a gzip+base64url encoded status list`; `returns true when bit is set` |
| **R-L2-9** | `mcp-server/.../claimPredicates.test.js`, `delegate.test.js` | `returns satisfied when all predicates pass`; `authorizes when predicate $gte is satisfied`; `denies when required claim is missing from VC` |
| **R-L2-10** | `mcp-server/.../claimPredicates.test.js` | `numeric-looking string fails $gte`; `boolean true fails $gt (no coercion to 1)`; `null fails $gte (no coercion to 0)`; `number is not in a string set` |
| **R-L2-11** | `mcp-server/.../verifyChain.test.js` | `authorizes a valid 2-hop chain`; `authorizes a valid 3-hop chain`; `denies when the leaf controller is not the expected agent` |
| **R-L2-12** | `mcp-server/.../verifyChain.test.js` | `denies a delegation whose expiry was extended`; `denies when the root capability does not match`; `denies a tampered delegation`; `denies when the expected action is not what the capability permits` |

## Cross-cutting

| Req | Test file | Proving test(s) |
|-----|-----------|-----------------|
| **R-X-1** | `demo-agent/.../agent.test.js` | `canary: denies a verdict reached WITHOUT calling the tool`; `canary: catches a verdict that CONTRADICTS the tool result` |
| **R-X-2** | `demo-agent/.../agent.test.js`, `scenarios.test.js` | `never leaks the sentinel secret in output or tool args`; `returns a sentinel and a still-valid scenario` |
| **R-X-3** | `mcp-server/.../documentLoader.test.js` | `serves the agent credential context offline`; `returns the same cached object on repeated did:key loads`; `resolves a did:key URL to an unwrapped document` |
| **R-X-4** | `mcp-server/.../delegate.test.js`, `revocation.test.js` | structured results throughout, e.g. `denies when required claim has wrong value`; `handles invalid encodedList` |

## L3 — Selective disclosure (Phase 2, ecdsa-sd-2023)

| Req | Test file | Proving test(s) |
|-----|-----------|-----------------|
| **R-L3-1** | `mcp-server/.../vcSd.test.js`, `sdTools.test.js` | `reveals only the requested claim, hiding the rest`; `reveals only the requested flag, hiding the rest` |
| **R-L3-2** | `mcp-server/.../vcSd.test.js`, `sdTools.test.js` | `rejects a tampered reveal document (R-L3-2)`; `denies a tampered reveal document` |
| **R-L3-3** | `mcp-server/.../sdTools.test.js` | `verifies a genuine reveal document end-to-end` (issuer + validity present, PII absent) |
| **R-L3-5** | `demo-agent/.../wallet.test.js`, `sdEval.test.js` | `never includes the birthdate anywhere in the reveal document`; `never leaks the birthdate in output or tool args (R-L3-5)` |
| **R-L3-6** | `mcp-server/.../sdTools.test.js` | `rejects a request for more than two age_over_NN flags (R-L3-6)` |

(R-L3-4 is a SHOULD satisfied by documentation — see `docs/phase-2-spec.md`
§2/§6 and the README; no test applies.)

## L3 — Unlinkable selective disclosure (Phase 2.5, bbs-2023)

| Req | Test file | Proving test(s) |
|-----|-----------|-----------------|
| **R-L3-7** | `mcp-server/.../vcSd.test.js`, `sdTools.test.js`; `demo-agent/.../sdEval.test.js` | `produces unlinkable derivations: two reveals differ yet both verify (R-L3-7)`; `produces unlinkable derivations through the tool layer (R-L3-7)`; `produces unlinkable disclosures: two requests to the wallet yield different proofs (R-L3-7)` |
| **R-L3-9** | `mcp-server/.../vcSd.test.js`, `sdTools.test.js` | `rejects a tampered bbs-2023 reveal document`; `issues, derives, and verifies end-to-end` |

## Out of scope

| Req | Status |
|-----|--------|
| **R-L3-8** (token bridging, audit trails) | Not implemented. |

---

## Coverage summary

| Level | Requirements | Mapped to tests |
|-------|--------------|-----------------|
| L1 | R-L1-1 … R-L1-6 (6) | 6 / 6 |
| L2 | R-L2-1 … R-L2-12 (12) | 12 / 12 |
| Cross-cutting | R-X-1 … R-X-4 (4) | 4 / 4 |
| L3 selective disclosure (Phase 2) | R-L3-1…6 (6; R-L3-4 is doc-only) | 5 / 5 tested |
| L3 unlinkable disclosure (Phase 2.5) | R-L3-7, R-L3-9 (2) | 2 / 2 tested |
| **In-scope total** | **30** | **29 tested + 1 doc** |
| Later | R-L3-8 (1) | deferred |

Every in-scope MUST/SHOULD has at least one proving test. The numbered steps of
the `check_delegation` pipeline (`mcp-server/lib/tools/delegate.js`) map 1:1 to
R-L2-2, R-L2-3/4/5/6, R-L2-7, and R-L2-9.

## Web shell (no new requirements)

The `web/` browser demo (Phase 3) adds **no new conformance requirements**. Its
HTTP endpoints are thin adapters that delegate to the same `mcp-server` tools
covered above — they introduce no new authorization logic, so they inherit the
existing rows. The shell adds one safety mechanism of its own, a response
sanitizer enforcing R-X-2 (no key material crosses to the client), proven by
`web/lib/__tests__/sanitize.test.js` and the canary assertions in the web
integration tests.
