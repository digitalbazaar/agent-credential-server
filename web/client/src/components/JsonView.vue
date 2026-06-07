<!--
  Copyright (c) 2026 Digital Bazaar, Inc.

  A read-only pretty-printed JSON block. Used to show the issued credential and
  the auth proof exactly as the server returned them (already sanitized).
-->
<script setup lang="ts">
import {computed} from 'vue';

const props = defineProps<{value: unknown}>();

const pretty = computed(() => JSON.stringify(props.value, null, 2));
</script>

<template>
  <pre class="json"><code>{{ pretty }}</code></pre>
</template>
