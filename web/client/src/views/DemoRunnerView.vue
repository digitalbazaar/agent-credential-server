<!--
  Copyright (c) 2026 Digital Bazaar, Inc.

  The applied-demo view (Cloudflare migration, CA DMV vehicle registration).
  Runs the real agent loop server-side and shows the tool-call trace alongside
  the authoritative tool decisions. The point it makes visible: the model
  orchestrates the tools, but the TOOLS decide — the verdict is never the
  model's prose. The model here is a deterministic mock (offline, no key).
-->
<script setup lang="ts">
import {type DemoRun, listDemos, runDemo} from '../api';
import {onMounted, ref} from 'vue';
import JsonView from '../components/JsonView.vue';

const names = ref<string[]>([]);
const selected = ref<string>('dmv');
const run = ref<DemoRun | null>(null);
const busy = ref(false);
const error = ref<string | null>(null);

onMounted(async () => {
  try {
    names.value = await listDemos();
  } catch(e) {
    error.value = String(e);
  }
});

/**
 * A decision is "granted" if its tool output is authorized or granted. Used
 * only for the badge color; the source of truth is the tool output itself.
 */
function isGranted(output: Record<string, unknown>): boolean {
  return output.granted === true || output.authorized === true;
}

async function go() {
  busy.value = true;
  error.value = null;
  run.value = null;
  try {
    run.value = await runDemo(selected.value);
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
      An agent acts on a human's behalf through scoped, fail-closed tools. The
      agent holds no production credentials and reaches no verdict itself — it
      calls the tools, and the tools decide. The model here is a deterministic
      mock; a live model can drive the same flow locally.
    </p>

    <div class="controls">
      <label for="demo">Demo</label>
      <select id="demo" v-model="selected" :disabled="busy">
        <option v-for="n in names" :key="n" :value="n">{{ n }}</option>
      </select>
      <button :disabled="busy" @click="go">
        {{ busy ? 'Running…' : 'Run demo' }}
      </button>
    </div>

    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="run" class="result">
      <h3>Tool calls (what the agent invoked, in order)</h3>
      <ol class="trace">
        <li v-for="(call, i) in run.toolCalls" :key="i">{{ call }}</li>
      </ol>

      <h3>Tool decisions (the authoritative outcomes)</h3>
      <div v-for="(d, i) in run.decisions" :key="i" class="decision"
        :class="isGranted(d.output) ? 'granted' : 'denied'">
        <div class="decision-head">
          <strong>{{ d.name }}</strong>
          <span class="badge-text">
            {{ isGranted(d.output) ? 'authorized' : 'denied / gated' }}
          </span>
        </div>
        <JsonView :value="d.output" />
      </div>

      <details class="cred">
        <summary>Agent's final message</summary>
        <p class="final">{{ run.finalText }}</p>
      </details>
    </div>
  </section>
</template>
