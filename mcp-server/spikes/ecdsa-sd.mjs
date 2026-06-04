/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * Phase 2 de-risk spike (docs/phase-2-spec.md).
 *
 * Proves one end-to-end selective-disclosure roundtrip on ecdsa-sd-2023 BEFORE
 * writing any Phase 2 lib code: issue a base proof -> holder derives a reveal
 * document disclosing only age_over_21 -> verifier verifies the derived proof,
 * and the birthdate / other claims are provably absent. Scratch artifact, not
 * production code: excluded from typecheck/test.
 *
 * Run: `node spikes/ecdsa-sd.mjs` from the mcp-server workspace.
 * Expected final line: `SPIKE OK`.
 *
 * Confirms for Phase 2:
 *   - ecdsa-sd-2023 three-cryptosuite split (sign/disclose/verify).
 *   - P-256 ECDSA keys + the did:key header for ecdsa-multikey.
 *   - mandatoryPointers (issuer/validity always revealed) vs selectivePointers
 *     (holder chooses which claims to disclose).
 *   - the reveal document genuinely omits unrevealed claims (the DOB).
 */
import * as vc from '@digitalbazaar/vc';
import * as EcdsaMultikey from '@digitalbazaar/ecdsa-multikey';
import {
  createDiscloseCryptosuite, createSignCryptosuite, createVerifyCryptosuite
} from '@digitalbazaar/ecdsa-sd-2023-cryptosuite';
import {DataIntegrityProof} from '@digitalbazaar/data-integrity';
import {driver as didKeyDriverFactory} from '@digitalbazaar/did-method-key';

// 1. did:key issuer on a P-256 ECDSA key (note the multikey header differs
//    from Ed25519's z6Mk — ecdsa-multikey provides the header to use).
const didKeyDriver = didKeyDriverFactory();
didKeyDriver.use({
  multibaseMultikeyHeader: 'zDna', // P-256 ecdsa-multikey prefix
  fromMultibase: EcdsaMultikey.from
});
const keyPair = await EcdsaMultikey.generate({curve: 'P-256'});
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

// 3. issue the base (SD) proof. mandatoryPointers = always revealed.
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
    age_over_65: false,
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

// 4. holder derives a reveal doc disclosing ONLY age_over_21
const discloseSuite = new DataIntegrityProof({
  cryptosuite: createDiscloseCryptosuite({
    selectivePointers: ['/credentialSubject/age_over_21']
  })
});
const revealed = await vc.derive({
  verifiableCredential: signed, suite: discloseSuite, documentLoader
});

// 5. assert minimality: the DOB and other claims must be gone
const subject = revealed.credentialSubject;
const leaked = ['birthdate', 'name', 'age_over_18', 'age_over_65']
  .filter(k => k in subject);
console.log('revealed subject keys:', Object.keys(subject));
if(leaked.length > 0) {
  console.error('LEAKED unrevealed claims:', leaked);
  process.exit(1);
}
if(subject.age_over_21 !== true) {
  console.error('age_over_21 not disclosed correctly:', subject.age_over_21);
  process.exit(1);
}

// 6. verify the derived proof
const verifySuite = new DataIntegrityProof({
  cryptosuite: createVerifyCryptosuite()
});
const result = await vc.verifyCredential({
  credential: revealed, suite: verifySuite, documentLoader
});
console.log('VERIFIED:', result.verified);
if(!result.verified) {
  console.error(JSON.stringify(result.error?.errors ?? result.error, null, 2));
  process.exit(1);
}
console.log('SPIKE OK');
