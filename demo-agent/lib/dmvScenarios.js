/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/*
 * Scenario builders for the CA DMV "register a vehicle" demo: a DMV-issued
 * driver credential, a DMV root capability over the registration resource, and
 * a scoped register-vehicle delegation from the DMV down to the agent, plus a
 * fresh agent auth proof.
 *
 * The pattern separates WHO the human is (the driver credential, a VC about
 * eligibility) from WHAT this agent may do (a scoped, time-boxed zcap
 * delegation). A single over-broad VC claim is deliberately avoided. The full
 * design is in docs/dmv-demo-spec.md.
 *
 * The driver credential carries license class, residency, and license validity
 * — but NOT the license number (data minimization: the action needs
 * eligibility, not identity-grade PII). The credential's revocation status is
 * an index into the DMV server's status list, checked in the tool layer.
 */
import {buildRootCapability, createZcapDocumentLoader}
  from 'mcp-server/lib/core/zcapChain.js';
import {delegateCapability, makeDelegationController}
  from 'mcp-server/lib/core/zcapDelegate.js';
import {
  deriveDidKeyIssuer, makeDidKeyDriver
} from 'mcp-server/lib/tools/didKeyContext.js';
import {generateChallenge, signingInput}
  from 'mcp-server/lib/core/challenge.js';
import {generateKeyPair, sign, toBase64url}
  from 'mcp-server/lib/core/crypto.js';
import {issueCredentialTool} from 'mcp-server/lib/tools/issue.js';

/** The protected action + its invocation target (the DMV registration API). */
export const REGISTER_ACTION = 'register-vehicle';
export const REGISTER_TARGET = 'https://dmv.ca.gov/api/vehicles/register';

/** The default driver-credential status-list index used in scenarios. */
export const DRIVER_STATUS_INDEX = 42;

/**
 * @typedef {import('mcp-server/lib/core/vc.js').DataIntegrityCredential}
 *   DataIntegrityCredential
 * @typedef {import('mcp-server/lib/core/zcapChain.js').RootCapability}
 *   RootCapability
 * @typedef {import('mcp-server/lib/core/zcapDelegate.js').DelegatedZcap}
 *   DelegatedZcap
 */

/**
 * @typedef {object} AuthProof
 * @property {string} nonce - The challenge nonce.
 * @property {number} issuedAt - Issued-at (unix seconds).
 * @property {number} expiresAt - Expiry (unix seconds).
 * @property {string} signatureBase64url - The agent's signature over the nonce.
 */

/**
 * @typedef {object} DmvScenario
 * @property {string} agentDid - The agent the credential + delegation target.
 * @property {DataIntegrityCredential} driverCredential - The DMV-issued driver
 *   credential (license class, residency, validity; no license number).
 * @property {Record<string, unknown>} requiredClaims - The claims the
 *   register-vehicle action requires.
 * @property {number} statusIndex - The credential's revocation index in the
 *   DMV status list.
 * @property {RootCapability} rootCapability - The DMV root capability over the
 *   registration resource.
 * @property {DelegatedZcap} delegation - The scoped register-vehicle delegation
 *   (DMV -> agent).
 * @property {AuthProof} [authProof] - A fresh agent auth proof, if requested.
 * @property {string} registerAction - REGISTER_ACTION (convenience).
 * @property {string} registerTarget - REGISTER_TARGET (convenience).
 */

/**
 * @typedef {object} BuildDmvScenarioOptions
 * @property {string} [residency] - The driver's residency state; default 'CA'.
 * @property {string} [licenseClass] - The driver's license class; default 'C'.
 * @property {boolean} [licenseValid] - The license-valid flag; default true.
 * @property {number} [credentialExpiresInSeconds] - Driver-credential TTL;
 *   default 3600. Negative makes it expired.
 * @property {number} [credentialValidFromInSeconds] - Seconds until the
 *   credential becomes valid; positive makes it not-yet-valid.
 * @property {string} [delegationAction] - The action the delegation grants;
 *   default REGISTER_ACTION. Override for the wrong-action case.
 * @property {string} [delegateToDid] - Delegate the capability to this DID
 *   instead of the agent; override for the wrong-agent case.
 * @property {boolean} [withAuthProof] - Include a fresh agent auth proof.
 * @property {boolean} [wrongAuthSignature] - Sign the auth proof with a
 *   different key (adversarial).
 * @property {boolean} [expiredChallenge] - Use an expired auth challenge.
 * @property {number} [statusIndex] - The driver-credential revocation index;
 *   default DRIVER_STATUS_INDEX.
 */

/**
 * Build the DMV register-a-vehicle scenario: a DMV-issued driver credential, a
 * DMV root capability, a scoped register-vehicle delegation to the agent, and
 * (optionally) a fresh agent auth proof. Override options drive the adversarial
 * cases.
 *
 * @param {BuildDmvScenarioOptions} [options] - Scenario overrides.
 * @returns {Promise<DmvScenario>} The scenario.
 */
export async function buildDmvScenario(options = {}) {
  const {
    residency = 'CA',
    licenseClass = 'C',
    licenseValid = true,
    credentialExpiresInSeconds = 3600,
    credentialValidFromInSeconds,
    delegationAction = REGISTER_ACTION,
    delegateToDid,
    withAuthProof = false,
    wrongAuthSignature = false,
    expiredChallenge = false,
    statusIndex = DRIVER_STATUS_INDEX
  } = options;

  const driver = makeDidKeyDriver();

  // the agent: a real did:key (VC subject, delegation recipient, auth-proof
  // signer all share this identity)
  const agentKp = await generateKeyPair();
  const {did: agentDid} = await deriveDidKeyIssuer(agentKp.privateKey, driver);

  // the DMV is the root authority: it issues the driver credential AND controls
  // the root capability over the registration resource
  const dmv = await makeDelegationController(driver);
  const dmvIssuerKp = await generateKeyPair();

  // the DMV-issued driver credential: eligibility claims only, no license
  // number (data minimization)
  const driverCredential = await issueCredentialTool({
    subjectDid: agentDid,
    claims: {residency, licenseClass, licenseValid},
    privateKeyBase64url: toBase64url(dmvIssuerKp.privateKey),
    expiresInSeconds: credentialExpiresInSeconds,
    validFromInSeconds: credentialValidFromInSeconds
  });

  // the DMV root capability over the registration resource, and a loader that
  // resolves the DMV did:key + the root offline
  const rootCapability = buildRootCapability({
    controller: dmv.did, invocationTarget: REGISTER_TARGET
  });
  const loader = createZcapDocumentLoader({
    didKeyDriver: driver, rootCapabilities: [rootCapability]
  });

  // the scoped delegation: DMV -> agent, register-vehicle only, short-lived
  const delegation = await delegateCapability({
    parent: rootCapability,
    signer: dmv.signer,
    toController: delegateToDid ?? agentDid,
    action: delegationAction,
    target: REGISTER_TARGET,
    expiresInSeconds: 900,
    loader
  });

  /** @type {DmvScenario} */
  const scenario = {
    agentDid,
    driverCredential,
    requiredClaims: {
      residency: 'CA',
      licenseValid: true,
      licenseClass: {$in: ['C', 'M']}
    },
    statusIndex,
    rootCapability,
    delegation,
    registerAction: REGISTER_ACTION,
    registerTarget: REGISTER_TARGET
  };

  if(withAuthProof) {
    const token = expiredChallenge ?
      {nonce: 'n', agentDid, issuedAt: 100, expiresAt: 200} :
      generateChallenge(agentDid, 300);
    const signingKp = wrongAuthSignature ? await generateKeyPair() : agentKp;
    const sigBytes = await sign(signingInput(token), signingKp.privateKey);
    scenario.authProof = {
      nonce: token.nonce,
      issuedAt: token.issuedAt,
      expiresAt: token.expiresAt,
      signatureBase64url: toBase64url(sigBytes)
    };
  }

  return scenario;
}
