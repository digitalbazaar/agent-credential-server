<!--
  Copyright (c) 2026 Digital Bazaar, Inc.

  One step in the issue -> present -> verify pipeline. Renders a title, a short
  description, and a pass/fail/pending state badge.
-->
<script setup lang="ts">
defineProps<{
  title: string;
  description: string;
  state: 'pending' | 'pass' | 'fail';
}>();

const badge: Record<string, string> = {
  pending: '·',
  pass: '✓',
  fail: '✗'
};
</script>

<template>
  <div class="step" :class="state">
    <span class="badge">{{ badge[state] }}</span>
    <div class="body">
      <span class="title">{{ title }}</span>
      <span class="desc">{{ description }}</span>
    </div>
  </div>
</template>
