/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Phase 1 step 3 de-risk spike (SPEC.md §6 / chain redesign).
 *
 * Proves an @digitalbazaar/zcap delegation chain end to end on did:key
 * controllers BEFORE replacing the hand-rolled chain. Scratch artifact,
 * excluded from typecheck/test.
 *
 * Run: `node spikes/zcap-delegation.mjs` from the mcp-server workspace.
 * Expected final line: `CHAIN VERIFIED: true`.
 *
 * Confirmed versions (pinned in package.json):
 *   @digitalbazaar/zcap                     9.0.1
 *   @digitalbazaar/zcap-context             2.0.1
 *   @digitalbazaar/data-integrity-context   2.0.1
 *   jsonld-signatures                       11.6.0
 *
 * Findings that the chain migration must carry forward:
 *   1. zcap ACCEPTS our DataIntegrityProof + eddsa-rdfc-2022 suite — no legacy
 *      Ed25519Signature2020 is required. The reference impl stays single-suite
 *      (the delegation proof above prints "DataIntegrityProof eddsa-rdfc-2022").
 *   2. did:key controllers compose natively: did:key documents already expose
 *      capabilityDelegation/capabilityInvocation relationships, so
 *      methodFor({purpose: 'capabilityDelegation'}) yields the signing key id.
 *   3. The document loader MUST serve two more contexts offline beyond the VC
 *      ones: the zcap context (via zcap.extendDocumentLoader) and
 *      https://w3id.org/security/data-integrity/v2 (via
 *      @digitalbazaar/data-integrity-context). The VC2 loader alone is not
 *      enough for a bare zcap document.
 *   4. zcap enforces expiry attenuation: each child delegation's `expires` must
 *      be no less restrictive (<=) than its parent's. Use a shared or
 *      monotonically-tightening expiry, not Date.now()+offset per link.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import * as diContext from '@digitalbazaar/data-integrity-context';
import * as vcjs from '@digitalbazaar/vc';
import * as zcap from '@digitalbazaar/zcap';
import jsigs from 'jsonld-signatures';
import {createDocumentLoader} from '../lib/core/documentLoader.js';
import {cryptosuite as eddsaRdfc2022}
  from '@digitalbazaar/eddsa-rdfc-2022-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';

const {CapabilityDelegation, createRootCapability} = zcap;

// --- did:key controller setup ---
const didKeyDriver = didKeyDriverFactory();
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519Multikey.from
});

/**
 * Make a did:key controller with a signer bound to its key id.
 *
 * @returns {Promise<{did: string, keyId: string, signer: object}>} controller
 */
async function makeController() {
  const keyPair = await Ed25519Multikey.generate();
  const {didDocument, methodFor} = await didKeyDriver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  // did:key documents expose capabilityDelegation/Invocation relationships
  const vm = methodFor({purpose: 'capabilityDelegation'});
  keyPair.id = vm.id;
  keyPair.controller = didDocument.id;
  return {did: didDocument.id, keyId: vm.id, signer: keyPair.signer()};
}

const alice = await makeController(); // root controller
const bob = await makeController(); // delegate 1
const carol = await makeController(); // delegate 2 (leaf agent)
console.log('alice(root):', alice.did);
console.log('bob:', bob.did);
console.log('carol(leaf):', carol.did);

// document loader that also serves root zcaps
const baseLoader = createDocumentLoader({
  didKeyDriver,
  fallbackLoader: vcjs.defaultDocumentLoader
});
const rootZcaps = new Map();
const loader = zcap.extendDocumentLoader(async function(url) {
  if(rootZcaps.has(url)) {
    return {contextUrl: null, documentUrl: url, document: rootZcaps.get(url)};
  }
  // serve the data-integrity contexts offline (zcap docs reference v2)
  if(diContext.contexts.has(url)) {
    return {
      contextUrl: null, documentUrl: url, document: diContext.contexts.get(url)
    };
  }
  return baseLoader(url);
});

const suite = () => new DataIntegrityProof({cryptosuite: eddsaRdfc2022});

// single expiry so each child is no less restrictive than its parent
const expires = new Date(Date.now() + 3600000).toISOString();

// --- 1. root capability (alice controls a resource) ---
const target = 'https://resource.example/age-gated';
const rootCapability = createRootCapability({
  controller: alice.did,
  invocationTarget: target
});
rootZcaps.set(rootCapability.id, rootCapability);
console.log('root zcap id:', rootCapability.id);

// --- 2. alice delegates to bob ---
const bobZcap = {
  '@context': ['https://w3id.org/zcap/v1'],
  id: `urn:uuid:${crypto.randomUUID()}`,
  parentCapability: rootCapability.id,
  invocationTarget: target,
  controller: bob.did,
  allowedAction: 'access:age-restricted-content',
  expires
};
const bobDelegated = await jsigs.sign(bobZcap, {
  documentLoader: loader,
  suite: new DataIntegrityProof({
    signer: alice.signer, cryptosuite: eddsaRdfc2022
  }),
  purpose: new CapabilityDelegation({parentCapability: rootCapability.id})
});
console.log('bob delegation proof:', bobDelegated.proof?.type,
  bobDelegated.proof?.cryptosuite);

// --- 3. bob delegates to carol ---
const carolZcap = {
  '@context': ['https://w3id.org/zcap/v1'],
  id: `urn:uuid:${crypto.randomUUID()}`,
  parentCapability: bobDelegated.id,
  invocationTarget: target,
  controller: carol.did,
  allowedAction: 'access:age-restricted-content',
  expires
};
const carolDelegated = await jsigs.sign(carolZcap, {
  documentLoader: loader,
  suite: new DataIntegrityProof({
    signer: bob.signer, cryptosuite: eddsaRdfc2022
  }),
  purpose: new CapabilityDelegation({parentCapability: bobDelegated})
});
console.log('carol delegation signed');

// --- 4. verify the depth-2 delegation chain ---
const result = await jsigs.verify(carolDelegated, {
  documentLoader: loader,
  suite: suite(),
  purpose: new CapabilityDelegation({
    suite: suite(),
    expectedRootCapability: rootCapability.id
  })
});
console.log('CHAIN VERIFIED:', result.verified);
if(!result.verified) {
  console.error(JSON.stringify(
    result.error?.errors?.map(e => e.message) ?? result.error?.message,
    null, 2
  ));
  process.exit(1);
}
console.log('leaf controller:', carolDelegated.controller,
  '== carol:', carolDelegated.controller === carol.did);
