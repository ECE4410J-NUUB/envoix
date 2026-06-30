<script setup lang="ts">
import QrcodeVue from 'qrcode.vue';

defineProps<{
  value: string;
  label: string;
  size?: number;
}>();
</script>

<template>
  <div class="qr-card" :aria-label="label">
    <QrcodeVue :value="value" :size="size ?? 172" level="M" render-as="svg" />
  </div>
</template>
