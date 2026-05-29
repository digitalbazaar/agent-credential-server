/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
import { resolveDID } from "../core/resolver.js";

/**
 * @typedef {import("../core/resolver.js").DIDDocument} DIDDocument
 */

/**
 * @typedef {object} ResolveResult
 * @property {DIDDocument | null} didDocument
 * @property {string} [error]
 */

/**
 * @param {string} did
 * @returns {Promise<ResolveResult>}
 */
export async function resolveDIDTool(did) {
  const result = await resolveDID(did);
  if (result.didResolutionMetadata.error) {
    return { didDocument: null, error: result.didResolutionMetadata.error };
  }
  return { didDocument: result.didDocument };
}
