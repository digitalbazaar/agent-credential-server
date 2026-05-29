/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Phase 0 de-risk spike (SPEC.md §6).
 *
 * Proves one end-to-end VC 2.0 issue -> verify on the Digital Bazaar Data
 * Integrity stack BEFORE refactoring any working lib code. This is a scratch
 * artifact, not production code: it is excluded from typecheck/test and exists
 * to confirm the stack, the package versions, and the document-loader pattern.
 *
 * Run: `node spikes/data-integrity.mjs` from the mcp-server workspace.
 * Expected final line: `VERIFIED: true`.
 *
 * Confirmed versions (pinned in package.json):
 *   @digitalbazaar/vc                          7.3.0
 *   @digitalbazaar/data-integrity              2.5.0
 *   @digitalbazaar/eddsa-rdfc-2022-cryptosuite 1.3.0
 *   @digitalbazaar/ed25519-multikey            1.3.1
 *   @digitalbazaar/did-method-key              5.3.0
 *
 * Findings that Phase 1 must carry forward:
 *   1. Claim terms MUST be defined in @context. JSON-LD safe mode (on by
 *      default in the eddsa-rdfc-2022 canonize step) throws on any property
 *      that does not expand to an absolute IRI — e.g. a bare `over_21`. The
 *      real vc.js needs a published context defining the credential's claim
 *      vocabulary; the inline @vocab below is a spike shortcut only.
 *   2. The did:key driver's `get({url})` returns the DID document (or the
 *      resolved verification method when `url` carries a #fragment) DIRECTLY
 *      — it is not wrapped as `{didDocument}`. The document loader must return
 *      it as-is; destructuring `{didDocument}` yields undefined and breaks
 *      verification with "publicKeyMultibase property is required".
 *   3. The document loader is on the hot path for both issue and verify. It
 *      must be cached (Map below) and must NOT hit the network for did:key.
 */
import * as vc from '@digitalbazaar/vc';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {cryptosuite as eddsaRdfc2022}
  from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';

// 1. did:key issuer
const didKeyDriver = didKeyDriverFactory();
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519Multikey.from,
});
const keyPair = await Ed25519Multikey.generate();
const {didDocument, methodFor} = await didKeyDriver.fromKeyPair({
  verificationKeyPair: keyPair,
});
const did = didDocument.id;
const vm = methodFor({purpose: 'assertionMethod'});
keyPair.id = vm.id;
keyPair.controller = did;
console.log('issuer DID:', did);

// 2. cached document loader
const cache = new Map();
async function documentLoader(url) {
  if(cache.has(url)) {
    return cache.get(url);
  }
  if(url.startsWith('did:key:')) {
    // see finding 2: driver.get returns the document directly
    const document = await didKeyDriver.get({url});
    const doc = {contextUrl: null, documentUrl: url, document};
    cache.set(url, doc);
    return doc;
  }
  return vc.defaultDocumentLoader(url);
}

// 3. issue VC 2.0
const credential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    // see finding 1: define the demo claim term so safe mode keeps it
    {'@vocab': 'https://example.org/agent-credential#'},
  ],
  type: ['VerifiableCredential'],
  issuer: did,
  credentialSubject: {id: 'did:example:agent', over_21: true},
};
const suite = new DataIntegrityProof({
  signer: keyPair.signer(), cryptosuite: eddsaRdfc2022,
});
const signed = await vc.issue({credential, suite, documentLoader});
console.log('issued proof:', signed.proof.type, signed.proof.cryptosuite);

// 4. verify
const verifySuite = new DataIntegrityProof({cryptosuite: eddsaRdfc2022});
const result = await vc.verifyCredential({
  credential: signed, suite: verifySuite, documentLoader,
});
console.log('VERIFIED:', result.verified);
if(!result.verified) {
  console.error(JSON.stringify(result.error?.errors ?? result.error, null, 2));
  process.exit(1);
}
