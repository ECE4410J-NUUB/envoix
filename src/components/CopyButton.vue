<script setup lang="ts">
import { Check, Copy } from '@lucide/vue';

defineProps<{
  copied: boolean;
  label?: string;
}>();

defineEmits<{
  copy: [];
}>();
</script>

<template>
  <button class="copy-button" type="button" @click="$emit('copy')">
    <Check v-if="copied" :size="16" aria-hidden="true" />
    <Copy v-else :size="16" aria-hidden="true" />
    <span>{{ copied ? 'Copied' : label ?? 'Copy' }}</span>
  </button>
</template>
