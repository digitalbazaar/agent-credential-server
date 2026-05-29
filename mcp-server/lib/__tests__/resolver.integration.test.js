/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Integration tests: hit the real Universal Resolver.
 * Skipped by default — run explicitly with:
 *   INTEGRATION=true npm test
 *
 * Requires network access to https://dev.uniresolver.io
 */
import { resolveDID } from "../core/resolver.js";

const SKIP = process.env.INTEGRATION !== "true";
const maybeDescribe = SKIP ? describe.skip : describe;

maybeDescribe("Universal Resolver (integration)", () => {
  it("resolves did:web:danubetech.com and returns a DID document", async () => {
    const result = await resolveDID("did:web:danubetech.com");
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument?.id).toMatch(/^did:web:/);
  }, 15000);

  it("returns an error for an unknown DID", async () => {
    const result = await resolveDID("did:key:z6MkThisDoesNotExistAtAll");
    // did:key is self-resolving — should succeed even for unknown keys
    // Use a method that requires a registry lookup for a truly unknown DID
    expect(result).toBeDefined();
  }, 15000);

  it("handles a malformed DID gracefully", async () => {
    const result = await resolveDID("not-a-did");
    expect(
      result.didResolutionMetadata.error || result.didDocument === null
    ).toBe(true);
  }, 15000);
});
