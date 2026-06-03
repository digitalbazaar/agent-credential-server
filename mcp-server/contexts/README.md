<!--
Copyright (c) 2026 Digital Bazaar, Inc.
-->
# JSON-LD Contexts

Canonical JSON-LD `@context` documents for this project.

## `agent-credential-v1.jsonld`

The agent-credential claim context. It defines the demo claim terms
(`age_verified`, `over_21`, `delegatedFrom`, `role`) so JSON-LD safe mode keeps
them, with an `@vocab` fallback so arbitrary claims still expand to an absolute
IRI instead of being dropped.

- **Context IRI:** `https://w3id.org/agent-credential/v1`
- **Served by:** `lib/core/documentLoader.js`, which loads this file at module
  load and serves it offline for every request to the IRI above. The bytes
  served and the bytes that will be published are identical.

### Publishing (deferred)

The context IRI does not yet resolve over the network. Issued credentials embed
it as an identifier, and the bundled loader serves it locally, so nothing in
this repo depends on it resolving. Making it resolve is a separate step with two
open decisions:

1. **Final IRI.** Confirm whether `https://w3id.org/agent-credential/v1` is the
   right namespace, or whether a Digital Bazaar–owned path is preferred.
2. **Serving host.** Decide where the file is actually served from (e.g. GitHub
   Pages, a DB-owned host) before requesting the `w3id.org` redirect.

`w3id.org` is the W3C Permanent Identifier Community Group redirect service: you
do not host files there. Publishing means opening a PR against
[perma-id/w3id.org](https://github.com/perma-id/w3id.org) that adds an
`.htaccess` redirect from the chosen path to the serving host above. Keep the
served document byte-identical to this file.
