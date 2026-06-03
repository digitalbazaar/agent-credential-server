<!--
Copyright (c) 2026 Digital Bazaar, Inc.
-->
# Feature Spec: Phase 2 — Selective Disclosure (KYA-OS L3 step) **Status:** Draft for review (Engineering, DevOps, CTO, Privacy Officer) **Author:** DJ Scruggs **Date:** 2026-06-03 > Intended design, not current code. Phase 2 adds selective disclosure via **ecdsa-sd-2023** alongside the existing Ed25519 / eddsa-rdfc-2022 path. **bbs-2023** (unlinkable presentations) is captured as **Phase 2.5** (§9). API surface below was verified against the installed packages. ## 1. Summary A holder (the agent, or the user's wallet) presents a credential that proves a required age threshold — e.g. `age_over_21: true` — **without revealing** the birthdate or any other claim in the credential. This is the KYA-OS **L3** privacy step: data minimization enforced cryptographically, not by policy. Today every credential is signed with `eddsa-rdfc-2022`, which reveals the whole credential on verification. Selective disclosure needs a different cryptosuite and a different key type, added **additively** (the Ed25519 path is untouched), exactly as Phase 1 was staged. ### Why `age_over_NN` and not a birthdate predicate (grounding) A real issuer (a DMV) issues the license once — at 17, with a birthdate — and does not re-stamp it at 21. So "over 21" cannot be a fresh issuer assertion at request time, and it must not require revealing the birthdate (that defeats the whole point). The resolution, taken straight from the standards the relevant states use: - **ISO/IEC 18013-5** (the mDL standard behind the **California DMV Wallet**) models age as a family of `age_over_NN` **boolean data elements** (`age_over_18`, `age_over_21`, …) that the issuer precomputes from the DOB and that the holder **selectively discloses** — revealing only `age_over_21` while hiding the birthdate and the other flags. Disclosure is hashing-based selective disclosure, **not** a zero-knowledge range proof.
- ecdsa-sd-2023 does exactly this kind of selective _field_ disclosure, so the ISO model maps cleanly onto our stack.
  

This spec adopts the `age_over_NN` model. The time-dependence ("a flag computed at 17") is handled by the validity window + the monotonic property of age + a reissuance policy (see §5.1). Reference notes:

- ISO/IEC 18013-5 age_over_NN selective disclosure (boolean age attestations).
  
- California DMV Wallet + TruAge (age-verified purchasing; TruAge's one-time tokens add _unlinkability_, which is our Phase 2.5/bbs territory, §9).
  
- Utah SEDI — a policy-first, format-plural framework (leans on ISO 18013-5, OpenID4VP/VCI, W3C VCs); the `age_over_NN` model satisfies its data-minimization and offline-verifiability requirements.
  

These three references (with links) are surfaced in the README's Conformance section and in the demo's inline comments, not just here — so a reader sees the real-world grounding without opening the spec.
## 2. The three-cryptosuite flow (ecdsa-sd-2023)
ecdsa-sd-2023 splits into three cryptosuites (verified exports of `@digitalbazaar/ecdsa-sd-2023-cryptosuite`):

| Role | Factory | Who runs it |
| --- | --- | --- |
| **Sign** (issue base proof) | `createSignCryptosuite({mandatoryPointers})` | Issuer (the user) |
| **Disclose** (derive reveal doc) | `createDiscloseCryptosuite({selectivePointers})` | Holder (the agent) |
| **Verify** | `createVerifyCryptosuite()` | Resource server |

Flow:

1. **Issue (base proof).** The issuer signs the full credential with an ECDSA (P-256) key. `mandatoryPointers` mark claims that MUST always be revealed (e.g. `/issuer`, `/validUntil`). Output: a credential with an ecdsa-sd-2023 _base_ proof — the full credential plus disclosure data.
  
2. **Derive (selective).** The holder, using `selectivePointers` (JSON pointers to the claims to reveal, e.g. `/credentialSubject/over_21`), derives a **reveal document**: a new credential containing only the mandatory + selected claims and a _derived_ proof. The birthdate never appears.
  
3. **Verify.** The resource server verifies the derived proof against the issuer's ECDSA key. The proof is valid only if the revealed claims were genuinely in the issuer's original signature.
  

Privacy note (honest scoping): ecdsa-sd-2023 hides _which claims_ are shown, but derived presentations are **linkable** — two derivations from the same credential are correlatable. Unlinkability is Phase 2.5 (bbs-2023, §9).
## 3. Keys — a second key type, additively
- **New:** P-256 ECDSA keys via `@digitalbazaar/ecdsa-multikey` (`generate`, `from`, `toJwk`, `fromRaw`). These are distinct from the Ed25519 keys; SD requires ECDSA.
  
- **Unchanged:** the entire Ed25519 / eddsa-rdfc-2022 path (issue, verify, delegate, zcap) stays exactly as-is. Phase 2 is purely additive.
  
- **did:key:** ECDSA keys get a different multibase prefix; the did:key driver must be configured for the P-256 header alongside the existing Ed25519 one.
  
- **crypto.js / core split:** new pure helpers (`generateEcdsaMultikey`, etc.) live in `lib/core/`; the SD issue/derive/verify orchestration lives in `lib/core/vc-sd.js` (new) + `lib/tools/`, mirroring the existing core/tools separation.
  
## 4. New MCP tools
| Tool | Input | Output |
|---|---|---|
| `issue_sd_credential` | `subjectDid, claims, mandatoryClaims[], privateKeyMultibase, expiresInSeconds?` | credential with an ecdsa-sd-2023 base proof. `claims` includes the `age_over_NN` flags the issuer precomputes from the DOB. |
| `derive_disclosure` | `credential` (base proof), `revealClaims[]` (which claims to disclose, e.g. `["age_over_21"]`) | a reveal document (derived proof, only revealed claims) |
| `verify_disclosure` | `revealDocument` | `{valid, issuer, revealedClaims, reason?}` |

`check_delegation` gains an optional path: accept a reveal document and run the same step pipeline (subject binding, proof verify, validity, scope) against the _revealed_ claims. The authorization logic is unchanged — only the proof type and the claim set differ.
### 4.1 Holder model — the wallet seam (RESOLVED: Model B)
Two models were possible: (A) the agent holds the full credential and derives disclosures itself, or (B) the user's **wallet** holds the full credential and the agent receives only a pre-derived reveal document. **We build Model B** — it is the stronger privacy posture and matches the California DMV Wallet, where the holder's device derives and the verifier receives only the disclosure.

In a physical mDL exchange the wallet→verifier handoff is a QR code that bootstraps a device-to-device (BLE/NFC) presentation. We have no physical reader, so the analog is a **module seam**: the wallet is a separate module that holds the full credential and exposes only `requestDisclosure(claims[]) → revealDocument`. The agent calls it but cannot read into it, so the birthdate provably never enters agent-side code.

```text
Wallet (holds full credential)
  │  requestDisclosure(["age_over_21"])
  ▼
derive_disclosure  ──▶  reveal doc { age_over_21: true, + mandatory fields }
  │
  ▼
Agent  ──presents──▶  verify_disclosure / check_delegation  ──▶  Resource server
```

The leakage canary (§6) asserts the birthdate and other hidden fields never appear in agent output, the reveal document, or tool-call arguments — the test form of the QR-code privacy boundary.
### 4.2 Mandatory vs selective pointer policy
`mandatoryPointers` (always revealed) carry only what a verifier needs to **trust and bound** the credential. Everything that is substantive personal data is **selective**.

| Pointer | Mandatory? | Why |
|---|---|---|
| `/issuer` | ✅ mandatory | Without it the verifier can't resolve the key to check the proof — unverifiable. |
| `/validFrom`, `/validUntil` | ✅ mandatory | Without them expiry/not-yet-valid (R-L2-5/6) can't be enforced — a forever-valid token. |
| `/type`, `@context` | ✅ mandatory | Needed to interpret the document (JSON-LD processing). |
| `/credentialSubject/birthdate` | ❌ selective | Mandatory here would disclose the DOB on **every** presentation — defeats SD entirely. |
| `/credentialSubject/name`, `licenseNumber` | ❌ selective | Same: PII leaked on every presentation, even age-only ones. |
| each `/credentialSubject/age_over_NN` | ❌ selective | If `age_over_65` were mandatory, a liquor-store check (needs only `age_over_21`) would leak that the holder is a senior. Each flag must be independently selectable. |
| `/credentialSubject/id` | ⚠️ selective (noted) | Binding a reveal to the agent may need it, but it is also a correlation handle. Disclose only when subject-binding is required. |

Litmus test: if disclosing a field on **every** presentation would surprise or harm the holder, it must not be mandatory.
## 5. Demo (the L3 "wow")
Extends `demo-agent`. The issuer issues the fuller ISO `age_over_NN` set, and the agent obtains the reveal document from a simulated **wallet** module (§4.1):

1. The user's wallet holds an SD credential: `{ birthdate: "2000-01-01", age_over_18: true, age_over_21: true, age_over_65: false, name: "...", licenseNumber: "..." }` — the issuer precomputes the `age_over_NN` flags from the DOB; `issuer`, `type`, and the validity dates are mandatory.
  
2. A resource server requires `age_over_21: true`.
  
3. The agent asks the wallet for a disclosure of **only** `age_over_21`; the wallet derives the reveal document and returns it. The birthdate, name, licenseNumber, and other age flags never enter agent-side code.
  
4. The agent presents the reveal document; the server verifies and grants — and the document provably contains nothing beyond `age_over_21` + the mandatory fields.
  

The contrast with the Phase 1 demo is the headline: same grant decision, but the verifier learns _one bit_ and nothing more — matching how the California DMV Wallet proves "over 21" at a retail counter.
### 5.1 Age-flag freshness (the "issued at 17" problem)
`age_over_21` is a static field, but age is time-dependent — so how does a flag the DMV computed when the holder was 17 stay correct? Three properties keep it honest, the same way ISO mDL does:

- **Monotonicity.** Age only increases, so `age_over_NN` only ever flips `false → true`, never back. A flag is never wrongly `true`; at worst it is conservatively `false` before the threshold.
  
- **Validity window.** The credential's `validUntil` bounds how stale any flag can be; verification already enforces it (R-L2-5).
  
- **Reissuance.** The issuer reissues (or the wallet refreshes) the credential periodically, recomputing the flags from the DOB as of the new issuance date.
  

For the demo, the issuer computes `age_over_NN` from the DOB at issuance time, so the flags are correct by construction.

**Production note (out of demo scope):** a real deployment sets a refresh cadence and the wallet refreshes before `validUntil`. The threshold-crossing case — `age_over_21` flips the day the holder turns 21 — is the one that needs reissuance rather than just a long validity window; a production issuer schedules that reissuance from the DOB.
### 5.2 Reader-side disclosure limit
ISO/IEC 18013-5 caps a reader at requesting at most **two** `age_over_NN` elements in a single transaction (there is no business need for more, and more would needlessly narrow the holder's age). The `verify_disclosure` / `check_delegation` path enforces this: a request (or reveal document) disclosing more than two `age_over_NN` flags is rejected.
## 6. Privacy / security (Privacy by Design)
- **Data minimization, enforced cryptographically.** The verifier cannot see unrevealed claims even if it wanted to — the reveal document does not contain them. This is stronger than policy-based minimization.
  
- **Mandatory claims.** `issuer` and validity dates are mandatory so a reveal document is still verifiable and time-bound.
  
- **Linkability caveat — stated, not hidden.** ecdsa-sd-2023 derivations are correlatable; we document this and point to Phase 2.5 (bbs-2023) for unlinkability. A reference impl must not overclaim its privacy properties.
  
- **Leakage canary.** Extend the existing canary: assert the birthdate/other hidden claims never appear in the agent's output, the reveal document, or tool-call arguments.
  
- **Open privacy question:** who holds the SD credential and runs the derivation — the agent itself, or the user's wallet handing the agent only a pre-derived document? Affects where the full credential (with birthdate) lives. See §10.
  
## 7. Conformance (extends Phase 1.5 traceability)
New requirement IDs in `docs/conformance/REQUIREMENTS.md`:

| ID  | Kw  | Requirement |
| --- | --- | --- |
| R-L3-1 | MUST | A holder can derive a presentation revealing a subset of claims, hiding the rest. |
| R-L3-2 | MUST | A derived presentation verifies only if the revealed claims were in the issuer's original signature. |
| R-L3-3 | MUST | Mandatory claims (issuer, type, validity) are always present in a reveal document; substantive personal data (DOB, name, etc.) is never mandatory (§4.2). |
| R-L3-4 | SHOULD | The implementation documents that ecdsa-sd-2023 presentations are linkable (unlinkability → bbs-2023). |
| R-L3-5 | MUST | The birthdate and other hidden fields never enter agent-side code, output, or tool-call arguments (the wallet seam, §4.1). |
| R-L3-6 | MUST | A disclosure request for more than two `age_over_NN` flags is rejected (ISO 18013-5 reader limit, §5.2). |

Each gets a `// KYA-OS R-L3-n` citation and a row in `CONFORMANCE.md`. **Renumber (confirmed):** REQUIREMENTS.md currently lists R-L3-1/R-L3-2 as "deferred" placeholders in the out-of-scope table; the Phase 2 PR removes those placeholder rows and adds R-L3-1…R-L3-6 above as in-scope. The PR notes the renumber explicitly.
## 8. Eval target (AI Eval Gate)
- **Outcome:** the agent reaches the correct grant/deny decision **by deriving a minimal disclosure and calling the verify/delegation tool** — never by reasoning to a verdict, and never by presenting more claims than required.
  
- **Golden cases:** derive-and-verify `age_over_21` only → granted; tampered reveal doc → denied; reveal doc missing the required flag → denied; a derivation that leaks an extra claim (e.g. the birthdate) → flagged by the canary; `age_over_21` is `false` (under age) → denied.
  
- **Programmatic checks:** decision exact-match; verify-tool-called; **disclosure-minimality** assertion (the reveal doc contains exactly the mandatory + required claims, nothing more); leakage canary on the hidden claims.
  
## 9. Phase 2.5 — bbs-2023 (unlinkability), deferred
A later effort adds `@digitalbazaar/bbs-2023-cryptosuite` (BLS12-381 keys) for **unlinkable** presentations: two derivations from one credential cannot be correlated by colluding verifiers. Same derive/verify tool shape; stronger privacy claim ("the DMV cannot track which sites the agent visited"). Deferred because BBS tooling/interop is newer and it adds a third key type. The §4 tools are designed cryptosuite-agnostic where practical so 2.5 is mostly a new suite + key type, not a new flow.
## 10. Resolved decisions (from review, 2026-06-03)
1. **Holder model → Model B (wallet seam).** The wallet holds the full credential; the agent receives only a pre-derived reveal document. The birthdate never enters agent code. The QR-code/device handoff of physical mDL is expressed here as a module seam. See §4.1. (R-L3-5)
  
2. **Mandatory pointer policy → confirmed** `/issuer`**,** `/type`**+**`@context`**,** `/validFrom`**+**`/validUntil` **mandatory; all substantive personal data (birthdate, name, each** `age_over_NN`**, subject** `id`**) selective.** §4.2 gives the "why not mandatory" examples. (R-L3-3)
  
3. **Context terms → mirror ISO mDL term names** (`age_over_NN`, etc.) in the agent-credential context rather than inventing our own.
  
4. **Flag set → issue the fuller ISO** `age_over_NN` **set**, and **enforce the reader-side two-element limit** on disclosure. See §5.2. (R-L3-6)
  
5. **Reissuance → production note added** (§5.1); demo computes flags at issuance.
  
6. **Requirement renumbering → confirmed** (§7): replace the deferred R-L3-1/2 placeholders with in-scope R-L3-1…R-L3-6.
  
7. **References surfaced in README + demo comments**, not only the spec (§1).
  
### Still open (not blocking the build)
- **did:key vs did:web for the ECDSA issuer** — same question as Phase 1, now for the P-256 key. Demo uses `did:key`; `did:web` is a later option.
