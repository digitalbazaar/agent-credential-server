/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Predicate-based claim checking. Pure, no IO.
 */

/**
 * @typedef {string | number | boolean | null} ScalarValue
 */

/**
 * @typedef {object} PredicateOperators
 * @property {ScalarValue} [$eq]
 * @property {ScalarValue} [$ne]
 * @property {number} [$lt]
 * @property {number} [$lte]
 * @property {number} [$gt]
 * @property {number} [$gte]
 * @property {ScalarValue[]} [$in]
 * @property {ScalarValue[]} [$nin]
 */

/**
 * @typedef {ScalarValue | PredicateOperators} ClaimPredicate
 */

/**
 * @param {ClaimPredicate} p - The predicate value to test.
 * @returns {p is PredicateOperators} True if the value is an operators object.
 */
function isPredicateOperators(p) {
  return p !== null && typeof p === 'object' && !Array.isArray(p);
}

/**
 * @param {unknown} actual - The actual claim value.
 * @param {ClaimPredicate} predicate - The predicate to evaluate against.
 * @returns {boolean} True if the actual value satisfies the predicate.
 */
export function evaluatePredicate(actual, predicate) {
  if(!isPredicateOperators(predicate)) {
    return actual === predicate;
  }

  const ops = predicate;

  if('$eq' in ops && actual !== ops.$eq) {
    return false;
  }
  if('$ne' in ops && actual === ops.$ne) {
    return false;
  }

  if(ops.$lt !== undefined) {
    if(typeof actual !== 'number') {
      return false;
    }
    if(actual >= ops.$lt) {
      return false;
    }
  }
  if(ops.$lte !== undefined) {
    if(typeof actual !== 'number') {
      return false;
    }
    if(actual > ops.$lte) {
      return false;
    }
  }
  if(ops.$gt !== undefined) {
    if(typeof actual !== 'number') {
      return false;
    }
    if(actual <= ops.$gt) {
      return false;
    }
  }
  if(ops.$gte !== undefined) {
    if(typeof actual !== 'number') {
      return false;
    }
    if(actual < ops.$gte) {
      return false;
    }
  }

  if(ops.$in !== undefined &&
    !ops.$in.includes(/** @type {ScalarValue} */ (actual))) {
    return false;
  }
  if(ops.$nin !== undefined &&
    ops.$nin.includes(/** @type {ScalarValue} */ (actual))) {
    return false;
  }

  return true;
}

/**
 * @typedef {{satisfied: true} | {
 *   satisfied: false,
 *   failedKey: string,
 *   reason: string
 * }} CheckClaimsResult
 */

/**
 * @param {Record<string, unknown>} subject - The credential subject claims.
 * @param {Record<string, ClaimPredicate>} required - The required claim
 *   predicates, keyed by claim name.
 * @returns {CheckClaimsResult} Whether all required predicates are satisfied.
 */
export function checkClaims(subject, required) {
  for(const [key, predicate] of Object.entries(required)) {
    const actual = subject[key];
    if(!evaluatePredicate(actual, predicate)) {
      return {
        satisfied: false,
        failedKey: key,
        reason: `Claim '${key}' not satisfied ` +
          `(got ${JSON.stringify(actual)}, ` +
          `predicate: ${JSON.stringify(predicate)})`
      };
    }
  }
  return {satisfied: true};
}
