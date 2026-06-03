/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import {didWebToUrl} from '../core/didWeb.js';

describe('didWebToUrl', () => {
  it('maps a bare domain to its .well-known URL', () => {
    expect(didWebToUrl('did:web:example.com')).toBe(
      'https://example.com/.well-known/did.json'
    );
  });

  it('maps a domain with a path to a nested did.json URL', () => {
    expect(didWebToUrl('did:web:example.com:user:alice')).toBe(
      'https://example.com/user/alice/did.json'
    );
  });

  it('decodes a percent-encoded port in the host segment', () => {
    expect(didWebToUrl('did:web:localhost%3A3000')).toBe(
      'https://localhost:3000/.well-known/did.json'
    );
  });

  it('decodes a percent-encoded port with a path', () => {
    expect(didWebToUrl('did:web:example.com%3A8443:agents:bot')).toBe(
      'https://example.com:8443/agents/bot/did.json'
    );
  });

  it('returns null for a non-did:web DID', () => {
    expect(didWebToUrl('did:key:z6MkAbc')).toBeNull();
  });

  it('returns null for a did:web with an empty identifier', () => {
    expect(didWebToUrl('did:web:')).toBeNull();
  });

  it('returns null for a string that is not a DID', () => {
    expect(didWebToUrl('not-a-did')).toBeNull();
  });

  it('strips a DID URL fragment before building the host URL', () => {
    expect(didWebToUrl('did:web:example.com#key-1')).toBe(
      'https://example.com/.well-known/did.json'
    );
  });

  it('strips a DID URL query before building the host URL', () => {
    expect(didWebToUrl('did:web:example.com?versionId=1')).toBe(
      'https://example.com/.well-known/did.json'
    );
  });

  it('returns null when a path segment is empty', () => {
    expect(didWebToUrl('did:web:example.com::alice')).toBeNull();
  });
});
