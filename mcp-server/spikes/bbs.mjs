/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Phase 2.5 de-risk spike (docs/phase-2-spec.md §9).
 *
 * Proves the bbs-2023 selective-disclosure roundtrip AND its distinguishing
 * property — UNLINKABILITY — before writing any Phase 2.5 lib code: issue a
 * base proof with a BLS12-381 key, derive a reveal document disclosing only
 * age_over_21, verify it, then derive a SECOND reveal document from the same
 * credential and confirm its proof differs (two presentations a verifier
 * cannot correlate). Scratch artifact, excluded from typecheck/test.
 *
 * Run: `node spikes/bbs.mjs` from the mcp-server workspace.
 * Expected final line: `SPIKE OK (unlinkable)`.
 *
 * Confirms for Phase 2.5:
 *   - bbs-2023 uses the SAME three-cryptosuite split as ecdsa-sd-2023
 *     (createSign/Disclose/Verify) — only the key type differs.
 *   - BLS12-381 keys via @digitalbazaar/bls12-381-multikey (a 3rd key type).
 *   - the did:key header for BLS keys (zUC7…).
 *   - two derivations from one credential are NOT byte-identical → unlinkable.
 */
import * as Bls12381Multikey from '@digitalbazaar/bls12-381-multikey';
import * as vc from '@digitalbazaar/vc';
import {
  createDiscloseCryptosuite, createSignCryptosuite, createVerifyCryptosuite,
  requiredAlgorithm
} from '@digitalbazaar/bbs-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';

const algorithm = Array.isArray(requiredAlgorithm) ?
  requiredAlgorithm[0] : requiredAlgorithm;

// 1. did:key issuer on a BLS12-381 key
const keyPair = await Bls12381Multikey.generateBbsKeyPair({algorithm});
const header = keyPair.publicKeyMultibase.slice(0, 4); // zUC7
const didKeyDriver = didKeyDriverFactory();
didKeyDriver.use({
  multibaseMultikeyHeader: header,
  fromMultibase: Bls12381Multikey.from
});
const {didDocument, methodFor} = await didKeyDriver.fromKeyPair({
  verificationKeyPair: keyPair
});
const did = didDocument.id;
const vm = methodFor({purpose: 'assertionMethod'});
keyPair.id = vm.id;
keyPair.controller = did;
console.log('issuer DID:', did);

// 2. cached document loader (did:key offline, else default)
const cache = new Map();
async function documentLoader(url) {
  if(cache.has(url)) {
    return cache.get(url);
  }
  if(url.startsWith('did:key:')) {
    const document = await didKeyDriver.get({url});
    const doc = {contextUrl: null, documentUrl: url, document};
    cache.set(url, doc);
    return doc;
  }
  return vc.defaultDocumentLoader(url);
}

// 3. issue the base (SD) proof
const credential = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    {'@vocab': 'https://example.org/agent-credential#'}
  ],
  type: ['VerifiableCredential'],
  issuer: did,
  validFrom: new Date(Date.now() - 1000).toISOString(),
  validUntil: new Date(Date.now() + 3600_000).toISOString(),
  credentialSubject: {
    id: 'did:example:agent',
    birthdate: '2000-01-01',
    age_over_18: true,
    age_over_21: true,
    name: 'Pat Holder'
  }
};
const signSuite = new DataIntegrityProof({
  signer: keyPair.signer(),
  cryptosuite: createSignCryptosuite({
    mandatoryPointers: ['/issuer', '/validFrom', '/validUntil']
  })
});
const signed = await vc.issue({credential, suite: signSuite, documentLoader});
console.log('issued base proof:', signed.proof.cryptosuite);

// 4. derive a reveal doc disclosing ONLY age_over_21 (twice)
async function derive() {
  const suite = new DataIntegrityProof({
    cryptosuite: createDiscloseCryptosuite({
      selectivePointers: ['/credentialSubject/age_over_21']
    })
  });
  return vc.derive({
    verifiableCredential: signed, suite, documentLoader
  });
}
const reveal1 = await derive();
const reveal2 = await derive();

// 5. minimality: DOB and other claims gone
const subject = reveal1.credentialSubject;
const leaked = ['birthdate', 'name', 'age_over_18'].filter(k => k in subject);
console.log('revealed subject keys:', Object.keys(subject));
if(leaked.length > 0) {
  console.error('LEAKED:', leaked);
  process.exit(1);
}

// 6. unlinkability: the two derived proofs must NOT be byte-identical
const sameProof = reveal1.proof.proofValue === reveal2.proof.proofValue;
console.log('two derivations share a proofValue:', sameProof);
if(sameProof) {
  console.error('NOT unlinkable: derivations are identical');
  process.exit(1);
}

// 7. verify both derived proofs
const verifySuite = new DataIntegrityProof({
  cryptosuite: createVerifyCryptosuite()
});
for(const reveal of [reveal1, reveal2]) {
  const result = await vc.verifyCredential({
    credential: reveal, suite: verifySuite, documentLoader
  });
  if(!result.verified) {
    console.error(JSON.stringify(result.error?.errors ?? result.error, null, 2));
    process.exit(1);
  }
}
console.log('both reveal documents verified');
console.log('SPIKE OK (unlinkable)');
