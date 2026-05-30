/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
/**
 * CLI demo: age-gated access control via Verifiable Credentials.
 *
 * Scenarios:
 *   node lib/index.js valid     → present valid VC, access granted
 *   node lib/index.js tampered  → tampered VC, access denied
 *   node lib/index.js expired   → expired VC, access denied with reason
 *   node lib/index.js authn     → agent authentication via challenge-response.
 */
import {
  generateChallenge, signingInput
} from '../../mcp-server/lib/core/challenge.js';
import {
  generateKeyPair, sign, toBase64url
} from '../../mcp-server/lib/core/crypto.js';
import {issueCredential} from '../../mcp-server/lib/core/vc.js';
import {runAgent} from './agent.js';

process.on('unhandledRejection', reason => {
  console.error('Unhandled Rejection:', reason);
  process.exit(1);
});

async function main() {
  const scenario = process.argv[2] ?? 'valid';

  // Generate a fresh human keypair for this demo run
  const humanKeyPair = await generateKeyPair();
  const humanPublicKeyB64 = toBase64url(humanKeyPair.publicKey);

  const humanDid = `did:key:z_HUMAN_${humanPublicKeyB64.slice(0, 8)}`;
  const agentDid = `did:key:z_AGENT_demo`;

  if(scenario === 'authn') {
    // Authn demo: show challenge-response + delegation in one prompt
    const agentKeyPair = await generateKeyPair();
    const agentPublicKeyB64 = toBase64url(agentKeyPair.publicKey);

    // Pre-issue a deployment VC from human to agent
    const vc = await issueCredential(
      agentDid,
      {age_verified: true, over_21: true, role: 'deployer'},
      humanDid,
      humanKeyPair,
      3600
    );

    // Pre-generate a challenge and sign it (simulating agent's side)
    const token = generateChallenge(agentDid, 300);
    const sigBytes = await sign(signingInput(token), agentKeyPair.privateKey);
    const signatureBase64url = toBase64url(sigBytes);

    console.log(`\nScenario: authn`);
    console.log(`Human DID: ${humanDid}`);
    console.log(`Agent DID: ${agentDid}`);
    console.log(`VC JWT (first 60 chars): ${vc.jwt.slice(0, 60)}...`);

    const prompt = `
You are a resource server verifying an agent's credentials with authentication.

The agent's DID: ${agentDid}
The agent's public key (base64url): ${agentPublicKeyB64}

The agent presents a Verifiable Credential: ${vc.jwt}

The agent has pre-signed a challenge:
  nonce: ${token.nonce}
  issuedAt: ${token.issuedAt}
  expiresAt: ${token.expiresAt}
  signatureBase64url: ${signatureBase64url}

The human issuer DID: ${humanDid}
The human's private key (base64url, for re-issuing if needed): \
${toBase64url(humanKeyPair.privateKey)}

Instructions:
1. Use check_delegation with the authProof (nonce, issuedAt, expiresAt, \
signatureBase64url) to verify both the VC and the agent's identity.
   Note: For this demo, the DID resolution of local DIDs will fail — focus \
on the VC structural validation and authProof handling.
2. Report whether both the VC is valid and the agent authenticated successfully.
3. Report: ACCESS GRANTED or ACCESS DENIED with reason.
`.trim();

    await runAgent(prompt);
    return;
  }

  // Issue a VC from human to agent
  let vcJwt;

  if(scenario === 'expired') {
    const vc = await issueCredential(
      agentDid,
      {age_verified: true, over_21: true},
      humanDid,
      humanKeyPair,
      -1 // already expired
    );
    vcJwt = vc.jwt;
  } else {
    const vc = await issueCredential(
      agentDid,
      {age_verified: true, over_21: true},
      humanDid,
      humanKeyPair,
      3600 // 1 hour
    );
    vcJwt = vc.jwt;

    if(scenario === 'tampered') {
      // Tamper with the payload section
      const parts = vcJwt.split('.');
      const fakePayload = Buffer.from(
        JSON.stringify({
          iss: humanDid,
          sub: agentDid,
          iat: 0,
          vc: {credentialSubject: {id: agentDid, over_21: false}}
        })
      ).toString('base64url');
      vcJwt = `${parts[0]}.${fakePayload}.${parts[2]}`;
    }
  }

  console.log(`\nScenario: ${scenario}`);
  console.log(`Human DID: ${humanDid}`);
  console.log(`Agent DID: ${agentDid}`);
  console.log(`Human public key (b64url): ${humanPublicKeyB64}`);

  const prompt = `
You are an AI agent trying to access age-restricted content.

Your DID: ${agentDid}
You have a Verifiable Credential (JWT): ${vcJwt}

The resource server requires:
1. The VC must be addressed to you (sub = your DID)
2. The VC must have claims: over_21=true, age_verified=true
3. The VC must not be expired
4. The VC signature must be valid

IMPORTANT: For this demo, the issuer DID (${humanDid}) is a local test DID.
Instead of calling resolve_did (which would fail for a local DID), use \
verify_credential
to check the VC structure and expiry only, then determine access based on:
- Is the VC addressed to you?
- Does it have the required claims?
- Is it expired?
- Note: signature verification against a local DID is not possible without \
the DID document,
  so for this demo, focus on structural and claim validation.

Report clearly: ACCESS GRANTED or ACCESS DENIED, and why.
`.trim();

  await runAgent(prompt);
}

main();
