<!--
  Copyright (c) 2026 Digital Bazaar, Inc.

  The L3 selective-disclosure view. A wallet holds a full credential (birthdate
  and all); only one age_over_NN flag is disclosed to the verifier. The full
  credential never leaves the server-side wallet — this page only ever receives
  the reveal document. The unlinkable (bbs-2023) mode derives two reveals from
  the same credential and shows their proofs differ, so a verifier cannot
  correlate them.
-->
<script setup lang="ts">
import {
  type DisclosureResponse, type DisclosureVerdict,
  disclose, verifyDisclosure
} from '../api';
import {computed, ref} from 'vue';
import JsonView from '../components/JsonView.vue';

const mode = ref<'linkable' | 'unlinkable'>('linkable');
const result = ref<DisclosureResponse | null>(null);
const verdict = ref<DisclosureVerdict | null>(null);
const busy = ref(false);
const error = ref<string | null>(null);

const heldNotDisclosed = computed(() => {
  if(result.value === null) {
    return [];
  }
  return result.value.heldClaims.filter(
    c => !result.value!.disclosedClaims.includes(c));
});

// the two unlinkable proofs differ; surface that as a one-line confirmation
const proofsDiffer = computed(() => {
  if(result.value === null || result.value.secondReveal === null) {
    return null;
  }
  const a = JSON.stringify(result.value.reveal.proof);
  const b = JSON.stringify(result.value.secondReveal.proof);
  return a !== b;
});

async function run() {
  busy.value = true;
  error.value = null;
  result.value = null;
  verdict.value = null;
  try {
    result.value = await disclose(mode.value);
    verdict.value = await verifyDisclosure(
      result.value.reveal, result.value.cryptosuite);
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
      The wallet holds the full credential. Only one age flag crosses to the
      verifier — the birthdate and the rest never leave the wallet. The
      unlinkable mode (bbs-2023) proves the same fact twice without the two
      proofs being correlatable.
    </p>

    <div class="controls">
      <label for="mode">Cryptosuite</label>
      <select id="mode" v-model="mode" :disabled="busy">
        <option value="linkable">ecdsa-sd-2023 (linkable)</option>
        <option value="unlinkable">bbs-2023 (unlinkable)</option>
      </select>
      <button :disabled="busy" @click="run">
        {{ busy ? 'Deriving…' : 'Disclose age_over_21' }}
      </button>
    </div>

    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="result" class="result">
      <div class="split">
        <div class="pane wallet">
          <h3>Wallet (stays server-side)</h3>
          <ul>
            <li v-for="c in result.heldClaims" :key="c"
              :class="{ disclosed: result.disclosedClaims.includes(c) }">
              {{ c }}
              <span v-if="result.disclosedClaims.includes(c)"
                class="tag">disclosed →</span>
              <span v-else class="tag hidden">hidden</span>
            </li>
          </ul>
          <p class="note">
            {{ heldNotDisclosed.length }} claim(s) never leave the wallet.
          </p>
        </div>

        <div class="pane verifier">
          <h3>Verifier (sees only this)</h3>
          <JsonView :value="result.reveal.credentialSubject" />
          <div v-if="verdict" class="verdict"
            :class="verdict.valid ? 'granted' : 'denied'">
            <strong>{{ verdict.valid ? 'PROOF VALID' : 'PROOF INVALID' }}</strong>
            <span class="reason">
              {{ result.cryptosuite }}
              <template v-if="verdict.reason"> — {{ verdict.reason }}</template>
            </span>
          </div>
        </div>
      </div>

      <p v-if="proofsDiffer !== null" class="unlinkable-note"
        :class="{ ok: proofsDiffer }">
        Unlinkability: two derivations of the same fact produced
        {{ proofsDiffer ? 'different' : 'identical' }} proofs
        <template v-if="proofsDiffer">✓ (uncorrelatable)</template>.
      </p>

      <details class="cred">
        <summary>Reveal document (the only thing the verifier receives)</summary>
        <JsonView :value="result.reveal" />
      </details>
    </div>
  </section>
</template>
