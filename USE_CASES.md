# Use Cases

Real-world scenarios where DID-based agent authorization solves problems that OAuth, API keys, and session-based auth cannot.

The common pattern: a human (or institution) with a DID issues a scoped, time-limited credential to an agent. The agent presents it at runtime. Any verifier can check it without calling home. **The authority travels with the agent**, not with the session or the API key.

---

## Near-Term (Practical Today)

### 1. AI Assistant with Scoped Financial Permissions
You issue your AI agent a VC: `{ can_read_transactions: true, can_initiate_transfers: false, max_transfer_amount: 0 }`. The agent can query your bank data but any MCP tool that attempts a write checks `check_delegation` and blocks it. No OAuth scope renegotiation needed — the credential travels with the agent.

### 2. Enterprise AI with Role-Based Access
An HR manager issues a VC to an agent: `{ employee_id: "123", can_access_pii: false, department: "engineering" }`. When the agent tries to pull a report with salary data, the MCP server checks the VC claims and denies it. The agent's authority is defined by the credential, not by whatever system it happens to be running on.

### 3. Medical AI Scoped by Patient Consent
A patient issues a VC to a diagnostic agent: `{ patient_id: "abc", consented_data: ["labs", "imaging"], consented_purpose: "second_opinion" }`. The agent can only access the specific data types the patient signed off on. The audit trail is cryptographic, not just a log entry.

---

## Multi-Agent Systems

### 4. Agent-to-Agent Delegation Chains
An orchestrator agent receives a VC from a human, then issues a sub-credential to a sub-agent with narrower scope: `{ delegated_from: "orchestrator_did", allowed_actions: ["summarize"], cannot_subdelegate: true }`. Each hop in the chain is verifiable — you can reconstruct exactly who authorized what.

### 5. Contractor Agent with Time-Limited Access
You hire a coding agent from a third-party provider. Instead of giving it your API keys, you issue it a time-limited VC: `{ can_access_repo: "myorg/myapp", expires: "+7days", read_only: true }`. It expires automatically — no key rotation needed.

### 6. AI Hiring Pipeline
A recruiter agent has a VC from the company: `{ can_contact_candidates: true, approved_roles: ["senior-engineer"], budget_per_role: 150000 }`. It can reach out and negotiate salary up to the approved limit. Anything outside those claims gets blocked at the tool level.

---

## Regulatory / Compliance

### 7. GDPR Data Processing Agents
A data processing agent carries a VC encoding the legal basis for processing: `{ lawful_basis: "legitimate_interest", data_subjects: "EU", purpose: "fraud_detection" }`. Any tool that touches PII verifies the legal basis claim before proceeding. Compliance is enforced at the tool level, not just documented in a policy PDF.

### 8. KYC / Age Verification
The demo scenario, but production: instead of a self-signed key, the VC is signed by a regulated identity provider (Jumio, Onfido, etc.) whose DID is published and verifiable. The agent presents it to access age-restricted or jurisdiction-restricted services.

### 9. Healthcare Agents (HIPAA)
A care coordination agent carries a VC issued by the covered entity: `{ hipaa_authorized: true, treatment_relationship: true, patient_did: "did:..." }`. Tools that expose PHI check for this before responding.

---

## Infrastructure / DevOps

### 10. CI/CD Deployment Agents
An agent gets a short-lived VC to deploy: `{ environment: "staging", commit_sha: "abc123", approved_by: "did:key:engineer" }`. The deployment MCP tool verifies the VC before executing. No more shared deploy keys — every deployment is tied to a specific human approval.

### 11. Incident Response (Break Glass)
An on-call engineer issues an emergency VC: `{ break_glass: true, incident_id: "INC-042", expires: "+4hours" }`. The agent gets elevated access that automatically expires and is fully auditable.
