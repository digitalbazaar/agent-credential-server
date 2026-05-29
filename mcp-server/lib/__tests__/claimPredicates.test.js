/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { evaluatePredicate, checkClaims } from "../core/claimPredicates.js";

describe("evaluatePredicate", () => {
  describe("scalar (implicit $eq)", () => {
    it("matches equal string", () => expect(evaluatePredicate("alice", "alice")).toBe(true));
    it("rejects unequal string", () => expect(evaluatePredicate("alice", "bob")).toBe(false));
    it("matches equal number", () => expect(evaluatePredicate(42, 42)).toBe(true));
    it("matches equal boolean", () => expect(evaluatePredicate(true, true)).toBe(true));
    it("rejects mismatched boolean", () => expect(evaluatePredicate(false, true)).toBe(false));
    it("matches null", () => expect(evaluatePredicate(null, null)).toBe(true));
  });

  describe("$eq", () => {
    it("matches", () => expect(evaluatePredicate(5, { $eq: 5 })).toBe(true));
    it("rejects", () => expect(evaluatePredicate(5, { $eq: 6 })).toBe(false));
  });

  describe("$ne", () => {
    it("matches when not equal", () => expect(evaluatePredicate(5, { $ne: 6 })).toBe(true));
    it("rejects when equal", () => expect(evaluatePredicate(5, { $ne: 5 })).toBe(false));
  });

  describe("$lt / $lte", () => {
    it("$lt passes when less", () => expect(evaluatePredicate(18, { $lt: 21 })).toBe(true));
    it("$lt fails when equal", () => expect(evaluatePredicate(21, { $lt: 21 })).toBe(false));
    it("$lt fails when greater", () => expect(evaluatePredicate(25, { $lt: 21 })).toBe(false));
    it("$lte passes when equal", () => expect(evaluatePredicate(21, { $lte: 21 })).toBe(true));
    it("$lte passes when less", () => expect(evaluatePredicate(20, { $lte: 21 })).toBe(true));
    it("$lte fails when greater", () => expect(evaluatePredicate(22, { $lte: 21 })).toBe(false));
  });

  describe("$gt / $gte", () => {
    it("$gt passes when greater", () => expect(evaluatePredicate(25, { $gt: 21 })).toBe(true));
    it("$gt fails when equal", () => expect(evaluatePredicate(21, { $gt: 21 })).toBe(false));
    it("$gt fails when less", () => expect(evaluatePredicate(18, { $gt: 21 })).toBe(false));
    it("$gte passes when equal", () => expect(evaluatePredicate(21, { $gte: 21 })).toBe(true));
    it("$gte passes when greater", () => expect(evaluatePredicate(22, { $gte: 21 })).toBe(true));
    it("$gte fails when less", () => expect(evaluatePredicate(18, { $gte: 21 })).toBe(false));
  });

  describe("$in / $nin", () => {
    it("$in passes when value in array", () => expect(evaluatePredicate("admin", { $in: ["admin", "moderator"] })).toBe(true));
    it("$in fails when value not in array", () => expect(evaluatePredicate("guest", { $in: ["admin", "moderator"] })).toBe(false));
    it("$nin passes when value not in array", () => expect(evaluatePredicate("guest", { $nin: ["admin", "moderator"] })).toBe(true));
    it("$nin fails when value in array", () => expect(evaluatePredicate("admin", { $nin: ["admin", "moderator"] })).toBe(false));
  });

  describe("compound operators", () => {
    it("passes when all operators satisfied", () => expect(evaluatePredicate(25, { $gte: 21, $lt: 100 })).toBe(true));
    it("fails when one operator fails", () => expect(evaluatePredicate(18, { $gte: 21, $lt: 100 })).toBe(false));
    it("$ne + $gt compound", () => expect(evaluatePredicate(22, { $gt: 21, $ne: 25 })).toBe(true));
    it("$ne + $gt compound fails", () => expect(evaluatePredicate(25, { $gt: 21, $ne: 25 })).toBe(false));
  });

  describe("non-numeric comparison operators with non-numbers", () => {
    it("$lt returns false for non-number actual", () => expect(evaluatePredicate("foo", { $lt: 21 })).toBe(false));
    it("$gt returns false for non-number actual", () => expect(evaluatePredicate("foo", { $gt: 0 })).toBe(false));
  });
});

describe("checkClaims", () => {
  const subject = { age: 25, role: "admin", verified: true, name: "Alice" };

  it("returns satisfied when all predicates pass", () => {
    const result = checkClaims(subject, { age: { $gte: 21 }, role: "admin", verified: true });
    expect(result.satisfied).toBe(true);
  });

  it("returns satisfied for empty required claims", () => {
    const result = checkClaims(subject, {});
    expect(result.satisfied).toBe(true);
  });

  it("returns not satisfied with failedKey when predicate fails", () => {
    const result = checkClaims(subject, { age: { $gte: 30 } });
    expect(result.satisfied).toBe(false);
    if (!result.satisfied) {
      expect(result.failedKey).toBe("age");
      expect(result.reason).toMatch(/age/);
    }
  });

  it("returns not satisfied when claim is missing", () => {
    const result = checkClaims(subject, { missingClaim: true });
    expect(result.satisfied).toBe(false);
    if (!result.satisfied) {
      expect(result.failedKey).toBe("missingClaim");
    }
  });

  it("returns not satisfied with first failing key", () => {
    const result = checkClaims(subject, { age: { $gte: 21 }, role: "guest" });
    expect(result.satisfied).toBe(false);
    if (!result.satisfied) {
      expect(result.failedKey).toBe("role");
    }
  });

  it("backward-compat: scalar equality still works", () => {
    const result = checkClaims(subject, { age: 25, role: "admin" });
    expect(result.satisfied).toBe(true);
  });
});
