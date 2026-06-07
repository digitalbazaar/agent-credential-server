<!-- Copyright (c) 2026 Digital Bazaar, Inc. -->
# web — browser demo

A browser demo of the KYA-OS L1/L2/L3 flows. A thin Fastify HTTP shell over the
existing verification core (`mcp-server` + `demo-agent`), plus a Vue 3 client.
No crypto or VC logic lives here — the shell only composes the already-tested
tools, and every response is sanitized so no key material reaches the browser.

## Layout

- `lib/` — the Fastify server (plain JS + JSDoc, DB house style).
  - `server.js` — routes + static serving. `buildApp()` / `start()`.
  - `handlers.js` — framework-agnostic request handlers.
  - `scenarios.js` — the name→builder registry over demo-agent scenarios.
  - `sanitize.js` — the response sanitizer (the leakage canary, in code).
- `client/` — the Vue 3 + Vite single-page app (its own TypeScript toolchain).
- `public/` — the built client (generated; gitignored).

## Run it

Two terminals in development (the Vite dev server proxies `/api` to Fastify):

```sh
# terminal 1 — the API server
npm run start --workspace web

# terminal 2 — the client dev server (hot reload)
cd web/client && npm install && npm run dev
```

Or build the client once and let Fastify serve everything on one origin:

```sh
cd web/client && npm install && npm run build   # → web/public
npm run start --workspace web                    # serves the SPA + the API
```

## API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/scenarios` | List the available scenario names. |
| GET | `/api/scenario/:name` | Build a real signed credential + DIDs (keys stripped). |
| POST | `/api/check-delegation` | Verify a credential against a requested action. |

The verdict always comes from the server's `check_delegation` tool, never the
browser (KYA-OS R-X-1). The site runs the same code the conformance tests cover.
