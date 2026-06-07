<!-- Copyright (c) 2026 Digital Bazaar, Inc. -->
# Plan: Web Demo for agent-credential-server (Phase 3)
**Status:** Draft for review. No code yet. **Date:** 2026-06-06 **Goal:** Run the KYA-OS L1/L2/L3 flows in a browser. See how delegated agent authorization works without a terminal, a clone, or an API key.

> This is a **plan**, not an implementation. It describes intended design. Confirm direction before any code lands.
## 1. Why
Today the only entry points are the MCP server (stdio, for MCP clients) and the demo-agent CLI (terminal, needs a model). Neither is shareable as a link. A reference implementation is more persuasive when a reviewer can _watch_ a credential get issued, delegated, verified, and denied — live, in a browser.

Audience: DIF WG reviewers, prospective integrators, internal demos. Optimize for "I understood the flow in two minutes," not for a production console.
## 2. Hard constraints (non-negotiable)
1. **The MCP server is stdio-only.** Browsers cannot speak it. The web app must reuse the same `lib/core` (pure) + `lib/tools` (orchestration) functions through a thin HTTP layer — NOT reimplement any crypto/VC logic.
  
2. **The tool is the authority, never the model** (R-X-1). The browser must not be able to forge a GRANTED. All verification runs server-side in the tested pure code; the client only renders results.
  
3. **No private keys or model keys in the browser** (R-X-2). Issuer/agent keys and any LLM API key stay server-side. The leakage-canary property must hold: no key material in any HTTP response.
  
4. **Offline-deterministic by default.** Like the eval, the default flows use `did:key` + bundled contexts + a mock/no model, so the site works with zero secrets. A live-model path is opt-in (server-side key).
  
5. **Plain JS + JSDoc, DB house style.** No TypeScript. Type-check via `tsc --noEmit --checkJs`. Same lint config.
  
## 3. Architecture: functional core, imperative shell
```
 browser (static SPA)
    │  HTTP/JSON (fetch)
    ▼
 web/ — HTTP shell (imperative)
    │  imports + composes
    ▼
 mcp-server/lib/tools/*  (existing orchestration)
 mcp-server/lib/core/*   (existing pure logic — UNCHANGED)
 demo-agent/lib/*        (existing scenario builders, tools, agent loop)
```

- **No business logic in** `web/`**.** Each endpoint is a thin adapter: parse request → call an existing `*Tool` / scenario builder → return its result object as JSON. This keeps the security boundary in already-tested code.
  
- The pure core stays untouched, so the 278 existing tests still cover the logic the website exposes. The web layer gets its own (smaller) shell tests.
  
## 4. Proposed shape
### 4a. New workspace: `web/`
A third npm workspace beside `mcp-server/` and `demo-agent/`.

- **Server: Fastify** (decided, §8) — fast, good JSON, small dep tree, schema
  validation built in for the input-boundary rule in §6.
  
- **Endpoints (all POST, JSON in/out, each maps to one existing function):**
  

  | Endpoint | Calls | Returns |
  |---|---|---|
  | `/api/scenario/:name` | a `demo-agent` scenario builder | the built VC + DIDs + required claims (keys stripped) |
  | `/api/check-delegation` | `checkDelegation` (tools/delegate.js) | `{authorized, reason}` |
  | `/api/verify-chain` | `verifyDelegationChainTool` | `{authorized, reason}` |
  | `/api/issue-sd` / `/api/derive` / `/api/verify-disclosure` | the SD tools | result objects |
  | `/api/run-demo/:name` | the `runAgent` loop (cloudflare/dmv/sd) | tool-call trace + tool verdict |

- **Key handling:** scenario builders generate ephemeral keys server-side per request; responses include only public artifacts (the VC, DIDs, the decision). A response sanitizer asserts no `privateKey`/`secretKeyMultibase`/ `signer` field escapes — the canary, enforced in code, not by convention.
### 4b. Client: Vue 3 + Vite (decided, §8)
- **Vue 3 single-file components, built with Vite.** The build step is isolated
  to the `web/` workspace; the server + reused `lib/*` stay build-less plain JS.
- Reactivity carries the adversarial-toggle UX (toggle → re-render verdict +
  reason + JSON) far more readably than hand-wired DOM updates.
- No React, so the React 19 RSC security rule does not apply here.
- **JSDoc/TS note:** Vue tooling is TS-first. Decide at W2 whether the client is
  JSDoc-typed (house style, against Vue's grain) or TS is scoped to the client
  only. The server and `lib/*` remain JSDoc.
  
### 4c. The three things the UI should make obvious
1. **Issue → delegate → verify** as a visible pipeline, step by step, with the actual VC/zcap JSON shown and each verification step's pass/fail + reason.
  
2. **Adversarial toggles**: flip a switch (tamper a claim, expire the VC, wrong agent, out-of-scope action, revoke) and watch the verdict flip to DENIED with the specific reason. This is the most convincing part — denial is the product.
  
3. **Selective disclosure**: show the full credential staying in the "wallet" and only one `age_over_NN` flag crossing to the verifier (and, for `bbs-2023`, that two disclosures don't correlate).
  
## 5. What we explicitly do NOT build (this phase)
- No user accounts, no persistence, no real wallet, no real registrar/Cloudflare calls (the demos stay simulated).
  
- No exposing raw signing endpoints that would let the browser mint arbitrary credentials with server keys beyond the demo scenarios.
  
- No L3-8 token bridging / audit trail (that is Phase 4).
  
## 6. Privacy & security review (DB design principles)
- **Attack surface:** every new endpoint is an input boundary. Validate request bodies server-side (schema), treat all input as untrusted, return result objects, never throw to the client. Rate-limit the model-backed endpoint.
  
- **Data minimization:** responses carry only what the UI renders; the sanitizer strips keys/signers. SD endpoints reveal only the requested claim.
  
- **Secrets:** any LLM key is server-side `.env`, gitignored. The default demo path needs no secret at all.
  
- **No secrets in errors/logs:** reason strings already avoid key material; re-audit at the HTTP boundary.
  
- **TLS / deploy:** if hosted, TLS-only. Static + a small Node server deploys to most PaaS; a serverless function per endpoint is also viable (deferred, §8).
  
## 7. Phasing (each its own PR, gate green between)
1. **W1 —** `web/` **workspace + HTTP shell + 2 read-only endpoints** (`/api/scenario/:name`, `/api/check-delegation`) + response sanitizer + shell tests. No UI yet (curl-tested).
  
2. **W2 — minimal UI** for the issue→delegate→verify pipeline with the adversarial toggles (the L1/L2 story). Vanilla JS.
  
3. **W3 — selective-disclosure UI** (`sd` + `sd-unlinkable`), wallet/verifier split visualization.
  
4. **W4 — applied-demo runner** (cloudflare/dmv) showing the tool-call trace and that the model never decides; optional live-model toggle (server key).
  
5. **W5 — polish + deploy doc**: README "Try it" link, a deploy recipe, and a note that the site runs the same code the conformance tests cover.
  
## 8. Resolved decisions (reviewed 2026-06-07)
1. **HTTP server: Fastify.** Confirmed.
2. **Client stack: Vue 3 + Vite (single-file components).** Confirmed. Accepts a
   build step, isolated to the `web/` workspace; the Fastify server and the
   reused `lib/core`/`lib/tools` stay build-less plain JS + JSDoc. No React, so
   the React 19 security rule does not apply. Pros weighed: reactivity fits the
   adversarial-toggle UX, SFCs keep each flow readable; con: Vue tooling is
   TS-first, so keep the `web/` client JSDoc-typed against the grain or scope TS
   to the client only (decide at W2).
3. **Hosting target: DEFERRED.** This may become a **separate repo**. Keep the
   `web/` layer cleanly decoupled (it only imports the published/relative
   `lib/*` functions) so it can be extracted later without a rewrite. Revisit
   deployment shape when that call is made — do not bake in a hosting assumption.
4. **Live model: mock-only on any public site; live runs behind a local flag.**
   Confirmed.
5. **Scope: demo site only.** No embeddable widget / published client package
   this phase.
6. **Conformance: a short note, not new rows.** The web endpoints introduce no
   new authorization logic — they delegate to the already-covered core — so
   `CONFORMANCE.md` gets a one-line pointer, not R-Wx requirements.

### Open implication from #3 (separate-repo possibility)
Because the web demo might be extracted to its own repo, W1 must treat the
reused `lib/*` as an **external-style dependency** (imported through the
workspace, never reaching into private internals). This keeps the seam clean for
a future split and is good hygiene regardless.
