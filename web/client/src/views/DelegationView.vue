<!--
  Copyright (c) 2026 Digital Bazaar, Inc.

  The L1/L2 pipeline view: pick a scenario (the happy path or an adversarial
  variant), watch a real credential get issued and presented, then verified by
  the server's checkDelegation tool. The verdict comes from the server, never
  from this page — the UI only renders it, and shows it against the expected
  outcome so the adversarial cases are self-evidently correct.
-->
<script setup lang="ts">
import {
  type DelegationVerdict, type ScenarioResponse,
  buildScenario, checkDelegation, listScenarios
} from '../api';
import {computed, onMounted, ref} from 'vue';
import JsonView from '../components/JsonView.vue';
import PipelineStep from '../components/PipelineStep.vue';

const names = ref<string[]>([]);
const selected = ref<string>('valid');
const scenario = ref<ScenarioResponse | null>(null);
const verdict = ref<DelegationVerdict | null>(null);
const busy = ref(false);
const error = ref<string | null>(null);

const issued = computed(() => scenario.value !== null);
const verified = computed(() => verdict.value !== null);

// GRANTED only when the server authorized; the page cannot forge this
const decision = computed<'GRANTED' | 'DENIED' | null>(() => {
  if(verdict.value === null) {
    return null;
  }
  return verdict.value.authorized ? 'GRANTED' : 'DENIED';
});

const matchesExpected = computed(() => {
  if(scenario.value === null || decision.value === null) {
    return null;
  }
  return decision.value === scenario.value.expected;
});

onMounted(async () => {
  try {
    names.value = await listScenarios();
  } catch(e) {
    error.value = String(e);
  }
});

async function run() {
  busy.value = true;
  error.value = null;
  scenario.value = null;
  verdict.value = null;
  try {
    scenario.value = await buildScenario(selected.value);
    verdict.value = await checkDelegation(scenario.value.scenario);
  } catch(e) {
    error.value = String(e);
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <section>
    <p class="sub">
      A human issues a scoped credential to an agent. Any verifier checks it
      against the issuer's DID — no central registry. Pick a scenario and watch
      it pass or fail. The verdict is the server's, not this page's.
    </p>

    <div class="controls">
      <label for="scenario">Scenario</label>
      <select id="scenario" v-model="selected" :disabled="busy">
        <option v-for="n in names" :key="n" :value="n">{{ n }}</option>
      </select>
      <button :disabled="busy" @click="run">
        {{ busy ? 'Running…' : 'Run' }}
      </button>
    </div>

    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="scenario" class="result">
      <p class="label">{{ scenario.label }}</p>

      <div class="pipeline">
        <PipelineStep
          title="1. Issue"
          description="The issuer signs a Verifiable Credential for the agent."
          :state="issued ? 'pass' : 'pending'"
        />
        <PipelineStep
          title="2. Present"
          description="The agent presents the credential to the verifier."
          :state="issued ? 'pass' : 'pending'"
        />
        <PipelineStep
          title="3. Verify"
          description="check_delegation re-verifies proof, expiry, claims."
          :state="verified
            ? (decision === 'GRANTED' ? 'pass' : 'fail')
            : 'pending'"
        />
      </div>

      <div v-if="decision" class="verdict" :class="decision.toLowerCase()">
        <strong>{{ decision === 'GRANTED' ? 'ACCESS GRANTED' :
          'ACCESS DENIED' }}</strong>
        <span class="reason">{{ verdict?.reason }}</span>
        <span
          class="expected"
          :class="{ ok: matchesExpected, bad: matchesExpected === false }"
        >
          expected {{ scenario.expected }}
          <template v-if="matchesExpected"> ✓</template>
        </span>
      </div>

      <details class="cred">
        <summary>Credential (issued, keys stripped by the server)</summary>
        <JsonView :value="scenario.scenario.credential" />
      </details>
      <details v-if="scenario.scenario.authProof" class="cred">
        <summary>Agent auth proof</summary>
        <JsonView :value="scenario.scenario.authProof" />
      </details>
    </div>
  </section>
</template>
