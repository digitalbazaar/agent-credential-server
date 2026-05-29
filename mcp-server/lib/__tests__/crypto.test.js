/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { generateKeyPair, sign, verify, toBase64url, fromBase64url } from "../core/crypto.js";

describe("crypto", () => {
  it("generates a keypair with correct key lengths", async () => {
    const kp = await generateKeyPair();
    expect(kp.privateKey).toHaveLength(32);
    expect(kp.publicKey).toHaveLength(32);
  });

  it("sign + verify roundtrip succeeds", async () => {
    const kp = await generateKeyPair();
    const msg = new TextEncoder().encode("hello world");
    const sig = await sign(msg, kp.privateKey);
    const ok = await verify(msg, sig, kp.publicKey);
    expect(ok).toBe(true);
  });

  it("verify fails for tampered payload", async () => {
    const kp = await generateKeyPair();
    const msg = new TextEncoder().encode("hello world");
    const sig = await sign(msg, kp.privateKey);
    const tampered = new TextEncoder().encode("hello world!");
    const ok = await verify(tampered, sig, kp.publicKey);
    expect(ok).toBe(false);
  });

  it("base64url encodes and decodes roundtrip", () => {
    const bytes = new Uint8Array([1, 2, 3, 255, 0, 128]);
    const encoded = toBase64url(bytes);
    expect(encoded).not.toContain("+");
    expect(encoded).not.toContain("/");
    expect(encoded).not.toContain("=");
    const decoded = fromBase64url(encoded);
    expect(decoded).toEqual(bytes);
  });
});
