/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Unit tests for the response sanitizer — the leakage canary enforced in code.
 * Adversarial cases (nested keys, arrays, signer functions, JWK private scalar)
 * outnumber the happy path; the property under test is that NO forbidden field
 * survives, at any depth.
 */
import {FORBIDDEN_KEYS, sanitize} from '../sanitize.js';

describe('sanitize', () => {
  it('passes through a clean object unchanged', () => {
    const input = {did: 'did:key:z6Mk', claims: {age_over_21: true}};
    const {value, stripped} = sanitize(input);
    expect(value).toEqual(input);
    expect(stripped).toEqual([]);
  });

  it('strips a top-level private key field', () => {
    const {value, stripped} = sanitize({
      did: 'did:key:z6Mk', privateKey: 'SECRET'
    });
    expect(value).toEqual({did: 'did:key:z6Mk'});
    expect(stripped).toContain('privateKey');
  });

  it('strips a nested secretKeyMultibase', () => {
    const {value, stripped} = sanitize({
      wallet: {credential: {id: 'urn:x'}, secretKeyMultibase: 'zSECRET'}
    });
    expect(/** @type {any} */ (value).wallet.secretKeyMultibase)
      .toBeUndefined();
    expect(/** @type {any} */ (value).wallet.credential.id).toBe('urn:x');
    expect(stripped).toContain('wallet.secretKeyMultibase');
  });

  it('strips forbidden fields inside arrays, recording the index path', () => {
    const {value, stripped} = sanitize({
      keys: [{publicKeyMultibase: 'zPub', privateKeyMultibase: 'zPriv'}]
    });
    expect(/** @type {any} */ (value).keys[0].publicKeyMultibase).toBe('zPub');
    expect(/** @type {any} */ (value).keys[0].privateKeyMultibase)
      .toBeUndefined();
    expect(stripped).toContain('keys[0].privateKeyMultibase');
  });

  it('strips a signer object and a bare signer function', () => {
    const {value, stripped} = sanitize({
      did: 'did:key:z6Mk',
      signer: {id: 'k', sign: () => 'sig'},
      raw: () => 'fn'
    });
    expect(/** @type {any} */ (value).signer).toBeUndefined();
    expect(/** @type {any} */ (value).raw).toBeUndefined();
    expect(stripped).toContain('signer');
    expect(stripped).toContain('raw');
  });

  it('strips the JWK private scalar d but keeps the public x', () => {
    const {value, stripped} = sanitize({
      jwk: {kty: 'OKP', crv: 'Ed25519', x: 'PUB', d: 'PRIV'}
    });
    expect(/** @type {any} */ (value).jwk.x).toBe('PUB');
    expect(/** @type {any} */ (value).jwk.d).toBeUndefined();
    expect(stripped).toContain('jwk.d');
  });

  it('matches forbidden keys case-insensitively', () => {
    const {stripped} = sanitize({PrivateKey: 'x', SECRETKEY: 'y'});
    expect(stripped).toContain('PrivateKey');
    expect(stripped).toContain('SECRETKEY');
  });

  it('does not mutate the input', () => {
    const input = {privateKey: 'SECRET', keep: 1};
    sanitize(input);
    expect(input.privateKey).toBe('SECRET');
  });

  it('handles primitives and null', () => {
    expect(sanitize(null).value).toBe(null);
    expect(sanitize(42).value).toBe(42);
    expect(sanitize('s').value).toBe('s');
  });

  it('lists every forbidden key in lowercase (registry sanity)', () => {
    for(const key of FORBIDDEN_KEYS) {
      expect(key).toBe(key.toLowerCase());
    }
  });
});
