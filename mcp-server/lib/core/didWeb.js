/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * The did:web identifier-to-URL transformation.
 * No IO — testable in isolation.
 *
 * Implements the did:web method's "Read (Resolve)" URL construction:
 *   1. Strip any DID URL fragment/query/path.
 *   2. Replace ":" in the method-specific id with "/".
 *   3. Percent-decode the host (a port arrives as "%3A").
 *   4. A bare host gets "/.well-known"; a host with a path does not.
 *   5. Append "/did.json".
 *
 * @see https://w3c-ccg.github.io/did-method-web/#read-resolve
 */

const DID_WEB_PREFIX = 'did:web:';

/**
 * Convert a did:web DID into the HTTPS URL of its DID document.
 *
 * @param {string} did - The DID to convert.
 * @returns {string | null} The HTTPS did.json URL, or null when `did` is not
 *   a well-formed did:web identifier.
 */
export function didWebToUrl(did) {
  if(typeof did !== 'string' || !did.startsWith(DID_WEB_PREFIX)) {
    return null;
  }

  // 1. Drop any DID URL fragment or query — only the DID itself maps to a URL
  const idWithParams = did.slice(DID_WEB_PREFIX.length);
  const id = idWithParams.split('#')[0].split('?')[0];
  if(id === '') {
    return null;
  }

  // 2. Split the method-specific id into host + optional path segments
  const segments = id.split(':');
  if(segments.some(segment => segment === '')) {
    return null;
  }

  // 3. Percent-decode the host so an encoded ":port" becomes a real port
  const host = decodeURIComponent(segments[0]);
  const pathSegments = segments.slice(1).map(decodeURIComponent);

  // 4. Bare host → /.well-known; host with a path → the path itself
  const pathPart = pathSegments.length > 0 ?
    pathSegments.join('/') :
    '.well-known';

  // 5. The DID document always lives at did.json
  return `https://${host}/${pathPart}/did.json`;
}
