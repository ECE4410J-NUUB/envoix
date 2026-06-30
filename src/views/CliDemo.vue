<script setup lang="ts">
import { TerminalSquare } from '@lucide/vue';

import { cliFlows } from '@/data/demo';
</script>

<template>
  <section class="workflow-grid cli-page">
    <div class="intro-panel">
      <p class="eyebrow">Current branch support</p>
      <h2>CLI workflows</h2>
      <p>
        The CLI demo mirrors the branch today: QR invite pairing, LAN mDNS discovery,
        and manual peer/token transfer for one file.
      </p>
    </div>

    <div class="flow-list">
      <article v-for="flow in cliFlows" :key="flow.title" class="flow-card">
        <div class="flow-heading">
          <TerminalSquare :size="20" aria-hidden="true" />
          <div>
            <h3>{{ flow.title }}</h3>
            <p>{{ flow.description }}</p>
          </div>
        </div>
        <pre v-for="command in flow.commands" :key="command"><code>{{ command }}</code></pre>
      </article>
    </div>

  </section>
</template>
