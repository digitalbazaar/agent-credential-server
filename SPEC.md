<!-- Copyright (c) 2026 Digital Bazaar, Inc. -->

# agent-credential-server — KYA-OS Reference Implementation Plan

**Goal.** Turn this repo into Digital Bazaar's *lowercase* reference
implementation of KYA-OS: a clean, readable, spec-traced MCP-I server built on
DB's real Verifiable Credential stack. Conformance is table stakes; readability
and spec-traceability are the point.

> Status: planning doc. No code written yet. This is the artifact to review
> before implementation.

---

## 1. What we're building (and not)

| | In scope | Out of scope |
|---|---|---|
| **Role** | A reference impl others read to understand KYA-OS | *The* WG-blessed reference impl (DIF/Vouched own that) |
| **Language** | Plain JavaScript (ESM) + **JSDoc** types — DB house style | TypeScript (repo currently is TS; must be converted) |
| **Stack** | `@digitalbazaar/vc` + Data Integrity as the primary path | Hand-rolled JWT/`@noble` as primary |
| **Levels** | L1 (legacy/JWT nod) + L2 (full) this phase | L3 selective disclosure → **Phase 2** |
| **License** | **BSD** (DB standard), public repo | — |
| **Proof** | Self-written conformance suite mapping spec MUSTs → tests | Official certification |

A reference impl has a specific bar:
1. Built on DB libraries, not hand-rolled crypto.
2. Written in DB house style — **plain JS + JSDoc, not TypeScript**.
3. Code structure traceable to spec sections (L1/L2/L3).
4. Passes a requirements suite (table stakes, not headline).

---

## 2. KYA-OS background (for spec-tracing)

KYA-OS ("Know Your Agent OS") — donated to DIF March 2026, developed by the
KYA-OS Task Force under DIF's Trusted AI Agents WG. MCP-I is the MCP binding.

**Conformance levels:**
- **L1 (Agent).** Agent has a stable DID registered at init. Delegation
  optional; may use legacy identifiers (OAuth/JWT).
- **L2 (Agent + User).** Both have DIDs. User issues a VC to the agent.
  Per-request edge verification enforces revocation, expiry, scoped access.
- **L3 (Agent + User + Service).** All three KYA-aware. Full VC lifecycle,
  **selective disclosure**, credential-to-token bridging, audit trails.

**Primitives:** DID methods `did:key` (ephemeral), `did:web` (persistent),
`did:ion` (anchored). Delegation VCs carry issuer DID, `credentialSubject` with
agent DID, a **scope array** of permitted actions, `credentialStatus` for
revocation, and a cryptographic proof.

Sources:
- https://blog.identity.foundation/kya-os/
- https://modelcontextprotocol-identity.io/docs/getting-started/faq

---

## 3. Where the repo stands today

Already implemented (more than the README admits) — but **all hand-rolled**:

| File | Does | Reference-impl verdict |
|---|---|---|
| `lib/crypto.ts` | Ed25519 via `@noble`, base64url helpers | **Replace** — use `@digitalbazaar/ed25519-multikey` |
| `lib/vc.ts` | Hand-rolled JWT VC issue/parse/verify | **Replace** — use `@digitalbazaar/vc` + Data Integrity |
| `lib/chain.ts` | Delegation-chain verify (continuity, cycles, depth, `delegatedFrom` hash) | **Keep logic, re-base** on DB-verified links |
| `lib/claimPredicates.ts` | `$eq/$gt/$in/...` scope checking | **Keep** — maps to KYA-OS scope array |
| `lib/revocation.ts` + `statusListFetcher.ts` | StatusList2021 bitstring | **Keep**, confirm vs DB `vc-status-list` |
| `lib/challenge.ts` | Nonce challenge/response auth | **Keep** — L2 agent authentication |
| `lib/resolver.ts` | Universal Resolver client | **Keep**, add native `did:key`/`did:web` |
| `jose` dependency | Unused (JWT is hand-rolled) | **Remove** |

Tools (`resolve`, `verify`, `issue`, `delegate`, `auth`, `verifyChain`) stay as
the MCP surface; their `lib/` internals get swapped underneath.

---

## 4. Target architecture (DB stack)

**Primary credential path → VC 2.0 + Data Integrity proofs.**

Library choices (verified against current npm/DB repos):
- `@digitalbazaar/vc` — issue / verify `VerifiableCredential`
- `@digitalbazaar/data-integrity` — `DataIntegrityProof` wrapper
- `@digitalbazaar/eddsa-rdfc-2022-cryptosuite` — **Ed25519 suite** (note:
  `eddsa-2022` is legacy; `eddsa-rdfc-2022` is current)
- `@digitalbazaar/ed25519-multikey` — key gen + multikey format
- `@digitalbazaar/did-method-key` + `@digitalbazaar/did-method-web` — native
  resolution; Universal Resolver kept as fallback for other methods
- Phase 2: `@digitalbazaar/ecdsa-sd-2023-cryptosuite` (selective disclosure is
  **ECDSA**, not Ed25519 — Phase 2 keys differ)

```text
src/
  lib/                         # pure, no IO (functional core)
    crypto.ts        → multikey gen/sign/verify (wraps ed25519-multikey)
    vc.ts            → issue/verify via @digitalbazaar/vc + data-integrity
    chain.ts         → delegation chain (re-based on DB-verified links)
    claimPredicates.ts → scope-array enforcement (unchanged)
    revocation.ts    → StatusList (reconcile w/ DB vc-status-list)
    challenge.ts     → nonce auth (unchanged)
  tools/                       # IO orchestration (imperative shell)
    resolve / verify / issue / delegate / auth / verifyChain
  documentLoader.ts            # NEW — cached JSON-LD context loader (required by Data Integrity)
```

**New concern: JSON-LD document loader.** `@digitalbazaar/vc` needs a document
loader for `@context` resolution. A reference impl must show a *correct, cached,
non-network-on-hot-path* loader. This is a teaching surface, not a footnote.

---

## 5. Spec-traceability (the reference-impl differentiator)

Two deliverables that distinguish this from "just clean code":

1. **`docs/conformance/REQUIREMENTS.md`** — every KYA-OS/MCP-I MUST/SHOULD
   extracted as a numbered checklist, each row linking to (a) the spec section
   and (b) the test that proves it.
2. **Per-level walkthrough docs** — `docs/L1.md`, `docs/L2.md` narrating the
   flow with code citations (`file:line`), so a reader maps spec → code.

Code-level: spec-section citations in comments at each enforcement point
(e.g. `// KYA-OS §L2: per-request revocation check`).

---

## 6. Phased plan

### Phase 0 — De-risk (before touching working code)
- Spike: issue + verify one **VC 2.0** credential with `@digitalbazaar/vc` +
  `eddsa-rdfc-2022` + a `did:key` issuer, end to end, in a scratch file.
- Confirm document-loader pattern and exact package versions.
- **Exit:** one green end-to-end Data Integrity issue→verify before refactoring.

### Phase 0.5 — TypeScript → JavaScript + JSDoc conversion
DB house style is plain JS + JSDoc. The repo is currently all `.ts`. Convert
**before** the lib swap so the swap lands in the target language, not twice.
- `.ts` → `.js`; replace TS types/interfaces with JSDoc `@typedef`/`@param`/
  `@returns`. Named input/output interfaces become `@typedef` objects.
- Drop `tsc` build; keep type-checking via `tsc --noEmit --checkJs` against
  JSDoc (or DB's configured checker). Update `package.json` scripts.
- `.js` import extensions already correct (NodeNext) — no change there.
- Tests: Jest config moves off `ts-jest`; run JS ESM directly.
- **Exit:** all existing tests green as JS; `typecheck` passes on JSDoc.

> Note: CLAUDE.md "Development Guidelines" still say TypeScript strict mode —
> update to "JS + JSDoc" as part of this phase.

### Phase 1 — DB-stack swap (TDD, lib-by-lib)
Order chosen so each layer rests on a tested one below it:
1. `crypto.ts` → `ed25519-multikey`. Red/green against existing crypto tests.
2. `documentLoader.ts` (new) + cached contexts.
3. `vc.ts` → `@digitalbazaar/vc` Data Integrity. Keep hand-rolled JWT path
   *only* behind an explicit `legacyJwt` flag = the L1 nod.
4. `resolver.ts` → native `did:key`/`did:web` + Universal Resolver fallback.
5. `chain.ts` re-based on DB-verified links.
6. Reconcile `revocation.ts` with DB status-list conventions.
7. Tools: rewire internals; MCP schemas largely unchanged.
- **Exit:** all tests green on DB stack; `jose` + `@noble` removed.

### Phase 1.5 — Reference-impl polish
- `REQUIREMENTS.md` + `docs/L1.md` + `docs/L2.md`.
- Spec-citation comments at enforcement points.
- README rewrite: lead with "DB reference implementation of KYA-OS L1/L2".
- Conformance suite green; map each MUST → test.

### Phase 2 — Selective disclosure (the L3 wow) — separate effort
- `ecdsa-sd-2023` (new ECDSA keys, not Ed25519).
- Demo: agent proves `over_21` without revealing birthdate / rest of VC.
- New tools: `derive_disclosure` / verify a derived presentation.

---

## 7. Demo-agent + the eval gate

The `demo-agent/` puts an LLM (Claude) in the runtime path. Per engineering
standards, **before** rebuilding it we define an eval target:
- **Outcome:** agent correctly decides authorized vs denied across scenarios.
- **Golden set:** ~50 labeled (VC, action) → expected decision + reason.
- **Programmatic check:** decision exact-match + `check_delegation` tool-call
  correctness (the *tool* is authoritative; the LLM only narrates).
- **Regression:** run golden set in CI; fail on any decision flip.

Design note: the LLM must **never** be the authority on access — it calls
`check_delegation` and reports the structured result. This keeps the security
boundary in tested pure code, not in the model.

---

## 8. Privacy / security review (DB design principles)

- **Data minimization:** scope arrays grant least privilege; Phase 2 selective
  disclosure is the data-minimization headline (reveal one claim, not the VC).
- **Private keys:** dev keys in gitignored `.env` only; never committed; the
  reference impl must model this, not shortcut it.
- **Edge verification:** every `check_delegation` re-verifies signature +
  expiry + revocation + scope per request — no cached "already authorized".
- **No secrets in logs / error reasons:** `reason` strings describe *why*
  denied, never leak key material or full credential contents.
- **Untrusted input:** every VC/JWT is untrusted until verified against a
  resolved DID; parse defensively, return result objects, never throw to caller.

---

## 9. Open questions (need answers before Phase 1)

1. ~~**DB project or personal?**~~ **RESOLVED:** Digital Bazaar repo, **public**,
   **BSD license**. Remote → `git@github.com:digitalbazaar/<repo>.git` when set up.
2. ~~**VC 1.1 vs 2.0?**~~ **RESOLVED:** VC 2.0 (`/ns/credentials/v2`) is primary.
3. **`did:web` issuer hosting** — do we add a `/.well-known/did.json` endpoint
   so a DB-hosted issuer is resolvable, or stay `did:key` only for the demo?
4. **KYA-OS scope vocabulary** — does the spec define a `scope`/`action`
   vocabulary we must match, or do we define our own and note the gap?
5. **Status list source of truth** — keep custom StatusList2021 or adopt
   `@digitalbazaar/vc-status-list` for authenticity? (Recommend: adopt DB's.)
