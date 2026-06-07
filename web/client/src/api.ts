/*!
 * Copyright (c) 2026 Digital Bazaar, Inc.
 */
// Typed client for the web shell API. The server is authoritative; this module
// only transports requests and types the JSON shapes the UI renders.

export interface ScenarioResponse {
  name: string;
  label: string;
  expected: 'GRANTED' | 'DENIED';
  scenario: {
    agentDid: string;
    credential: Record<string, unknown>;
    requiredClaims?: Record<string, unknown>;
    authProof?: Record<string, unknown>;
  };
}

export interface DelegationVerdict {
  authorized: boolean;
  reason: string;
}

const REQUESTED_ACTION = 'access:age-restricted-content';

async function getJson<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if(!res.ok) {
    throw new Error(`GET ${url} → ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export async function listScenarios(): Promise<string[]> {
  const {scenarios} = await getJson<{scenarios: string[]}>('/api/scenarios');
  return scenarios;
}

export async function buildScenario(name: string): Promise<ScenarioResponse> {
  return getJson<ScenarioResponse>(`/api/scenario/${encodeURIComponent(name)}`);
}

export async function checkDelegation(
  scenario: ScenarioResponse['scenario']
): Promise<DelegationVerdict> {
  const res = await fetch('/api/check-delegation', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({
      agentDid: scenario.agentDid,
      requestedAction: REQUESTED_ACTION,
      credential: scenario.credential,
      requiredClaims: scenario.requiredClaims ?? {},
      authProof: scenario.authProof
    })
  });
  return res.json() as Promise<DelegationVerdict>;
}
