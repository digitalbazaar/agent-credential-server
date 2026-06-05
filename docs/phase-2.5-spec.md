<!--
Copyright (c) 2026 Digital Bazaar, Inc.
-->
# Feature Spec: Phase 2.5 — Unlinkable Disclosure (bbs-2023)

**Status:** Draft for review (Engineering, DevOps, CTO, Privacy Officer)
**Author:** DJ Scruggs
**Date:** 2026-06-04

> Intended design, not current code. Phase 2.5 adds **unlinkable** selective
> disclosure via **bbs-2023**, alongside the Phase 2 ecdsa-sd-2023 path (which
> stays). API surface and the unlinkability property below were verified with a
> spike (`mcp-server/spikes/bbs.mjs` → `SPIKE OK (unlinkable)`).

## 1. Summary

Phase 2 (ecdsa-sd-2023) lets a holder reveal only `age_over_21` and hide the
birthdate — but its derived presentations are **linkable**: two disclosures
from the same credential carry correlatable signature data, so colluding
verifiers can tell it was the same credential each time. Phase 2.5 closes that
gap with **bbs-2023**: each derivation produces a fresh, uncorrelatable proof,
so a verifier (or a set of them) cannot link the agent's presentations across
uses.

Concretely: "the DMV-issued credential proves over-21 at site A and site B, and
A + B colluding cannot tell it was the same holder." That is the strongest
privacy property in the W3C Data Integrity family, and it is what makes this
more than "a different signature algorithm."

## 2. What changes vs Phase 2 — almost nothing but the keys

The spike confirmed the Phase 2 bet: **bbs-2023 uses the same three-cryptosuite
split** as ecdsa-sd-2023, so the flow is identical and most of the SD code is
reusable.

| | ecdsa-sd-2023 (Phase 2) | bbs-2023 (Phase 2.5) |
|---|---|---|
| Cryptosuites | `createSign/Disclose/VerifyCryptosuite` | **same names** |
| Flow | issue base → derive reveal → verify | **same** |
| Mandatory/selective pointers | yes | **same** |
| Key type | P-256 ECDSA (`ecdsa-multikey`) | **BLS12-381** (`bls12-381-multikey`) |
| did:key header | `zDna` | `zUC7` |
| Algorithm | — | `BBS-BLS12-381-SHA-256` (`Bls12381G2`) |
| Derivations correlatable? | **yes (linkable)** | **no (unlinkable)** |

So Phase 2.5 is **a third key type + a second SD cryptosuite**, not a new flow.

## 3. Keys — a third key type, additively

- **New:** BLS12-381 keys via `@digitalbazaar/bls12-381-multikey`
  (`generateBbsKeyPair({algorithm})`, `from`, `fromJwk`, `fromRaw`, `toJwk`).
  The algorithm comes from `bbs-2023-cryptosuite`'s `requiredAlgorithm`
  (`BBS-BLS12-381-SHA-256`).
- **Unchanged:** the Ed25519 (auth/zcap) and P-256 ECDSA (Phase 2 SD) paths
  stay exactly as-is. Phase 2.5 is purely additive — a third key alongside the
  two.
- **did:key:** BLS keys use the `zUC7` multibase header; the did:key driver is
  configured for it alongside Ed25519 (`z6Mk`) and P-256 (`zDna`).

## 4. Code reuse — generalize, don't duplicate

`lib/core/vcSd.js` already wraps issue/derive/verify around an injected
cryptosuite trio. Phase 2.5 should **parameterize the cryptosuite family**
rather than copy the module:

- Add `lib/core/bls.js` — the BLS12-381 multikey helpers (the analog of
  `ecdsa.js`).
- Generalize `vcSd.js` so the SD functions accept the cryptosuite factories (or
  a small "suite kind" discriminator: `ecdsa-sd-2023` | `bbs-2023`). The issue/
  derive/verify bodies are otherwise identical.
- Tool layer: either a `cryptosuite` option on the existing
  `issue_sd_credential` / `derive_disclosure` / `verify_disclosure` tools, or
  parallel `*_bbs` tools. **Recommendation:** an option, since the spike proved
  the call shape is identical — fewer tools, one code path.
- `sdContext.js` analog for the BLS did:key driver + loader.

Open design question (§9): option-on-existing-tools vs parallel tools.

## 5. Demo (the unlinkability "wow")

Extends the Phase 2 `sd` demo with an `sd-unlinkable` (or `--bbs`) variant:

1. The wallet holds a bbs-2023 credential with the `age_over_NN` flags.
2. The agent derives a reveal document twice (simulating two separate
   verifiers), disclosing only `age_over_21` each time.
3. The demo shows the two presentations **verify independently** yet carry
   **different proofs** — visually demonstrating a verifier cannot correlate
   them. The Phase 2 ecdsa-sd run, by contrast, is noted as linkable.

The headline: same minimal disclosure as Phase 2, plus "these two proofs of the
same fact cannot be tied together."

## 6. Privacy / security (Privacy by Design)

- **Unlinkability — now claimed, and provable.** Unlike Phase 2, we can state
  that presentations are uncorrelatable, and the demo + a test prove it (two
  derivations differ). This is the property TruAge's one-time tokens approximate
  operationally; BBS provides it cryptographically.
- **Same data minimization** as Phase 2 (reveal one flag, hide the rest).
- **Leakage canary** carries over: the birthdate never enters agent code,
  output, or tool args (the wallet seam, R-L3-5).
- **Honesty about maturity:** BBS cryptography and `bbs-2023` interop are newer
  than ECDSA. Document that ecdsa-sd-2023 remains the conservative default and
  bbs-2023 is the stronger-privacy option, so the reference impl does not
  overstate readiness.

## 7. Conformance (extends Phase 2)

New requirement IDs (promote R-L3-7 from "deferred"):

| ID | Kw | Requirement |
|----|----|-------------|
| R-L3-7 | MUST | A holder can derive an **unlinkable** presentation: two derivations from the same credential are not correlatable. |
| R-L3-9 | MUST | A bbs-2023 derived presentation verifies only if the revealed claims were in the issuer's original signature (the R-L3-2 property, for BBS). |

Each gets a `// KYA-OS R-L3-n` citation and a `CONFORMANCE.md` row. The
unlinkability test asserts two derivations produce different proofs and both
verify (as the spike does).

## 8. Eval target (AI Eval Gate)

- **Outcome:** the agent reaches the correct verdict by deriving a minimal
  bbs-2023 disclosure and verifying it — same tool-deference as Phase 2.
- **New programmatic check — unlinkability:** derive twice, assert the proofs
  differ and both verify. Plus the carried-over minimality + leakage-canary
  checks.
- The eval stays mock-model and offline (the crypto is real; the model is
  mocked), so CI is unaffected.

## 9. Open questions

1. **Tools: option vs parallel.** Add a `cryptosuite` option to the existing SD
   tools, or ship parallel `*_bbs` tools? (Lean: option — identical call shape.)
2. **vcSd.js generalization shape.** Pass the cryptosuite factories in, or a
   `kind` discriminator that selects them internally? Affects the tool surface.
3. **Default cryptosuite.** Keep ecdsa-sd-2023 as the default (conservative,
   mature) and bbs-2023 opt-in? (Lean: yes.)
4. **did:key driver multiplexing.** One loader configured for all three headers
   (`z6Mk`/`zDna`/`zUC7`), or per-suite loaders? Affects whether a single demo
   can mix key types.
5. **Demo framing.** A distinct `sd-unlinkable` scenario, or a `--bbs` flag on
   the existing `sd` scenario?
