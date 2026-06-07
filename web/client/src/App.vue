<!--
  Copyright (c) 2026 Digital Bazaar, Inc.

  The demo shell: a header and a tab switch between the L1/L2 delegation
  pipeline and the L3 selective-disclosure view. Each view talks to the web
  shell API; no verification happens in this page.
-->
<script setup lang="ts">
import DelegationView from './views/DelegationView.vue';
import DisclosureView from './views/DisclosureView.vue';
import {ref} from 'vue';

const tab = ref<'delegation' | 'disclosure'>('delegation');
</script>

<template>
  <main>
    <header>
      <h1>KYA-OS — agent credential verification</h1>
      <nav class="tabs">
        <button
          :class="{ active: tab === 'delegation' }"
          @click="tab = 'delegation'"
        >
          Delegation (L1/L2)
        </button>
        <button
          :class="{ active: tab === 'disclosure' }"
          @click="tab = 'disclosure'"
        >
          Selective disclosure (L3)
        </button>
      </nav>
    </header>

    <DelegationView v-if="tab === 'delegation'" />
    <DisclosureView v-else />
  </main>
</template>
