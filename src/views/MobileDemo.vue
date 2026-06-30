<script setup lang="ts">
import { computed, ref } from 'vue';
import { Camera, Clipboard, Download, FileUp, Send, Settings, Shuffle, Zap } from '@lucide/vue';

import CopyButton from '@/components/CopyButton.vue';
import DemoQr from '@/components/DemoQr.vue';
import { demoInvite, demoLink } from '@/data/demo';

type TabName = 'transfer' | 'receive' | 'send' | 'settings';

const activeTab = ref<TabName>('transfer');
const receiveToken = ref('');
const sendToken = ref('');
const inviteInput = ref('');
const serverUrl = ref('https://rendezvous.envoix.local');
const relayUrl = ref('turn://relay.envoix.local');
const speedLimit = ref(40);
const concurrentTransfers = ref(true);
const toast = ref('');
const copied = ref(false);
const selectedImage = ref('');
const selectedFile = ref('');

const tabs = [
  { id: 'transfer' as const, label: 'Transfer', icon: Shuffle },
  { id: 'receive' as const, label: 'Receive', icon: Download },
  { id: 'send' as const, label: 'Send', icon: Send },
  { id: 'settings' as const, label: 'Settings', icon: Settings },
];

const connections = [
  {
    peer: '192.168.1.24:53190',
    mode: 'LAN',
    direction: 'Upload to Pixel 8',
    speed: '42 MBps',
    eta: '00:18',
    totalSize: '1.8 GB',
    progress: 72,
  },
  {
    peer: 'relay.envoix.dev:443',
    mode: 'Relay',
    direction: 'Download from ThinkPad',
    speed: '11 MBps',
    eta: '01:06',
    totalSize: '860 MB',
    progress: 38,
  },
  {
    peer: 'p2p:12D3KooW7f',
    mode: 'P2P',
    direction: 'Upload to iPad',
    speed: '24 MBps',
    eta: '00:31',
    totalSize: '1.1 GB',
    progress: 58,
  },
  {
    peer: '10.0.0.42:49422',
    mode: 'Direct',
    direction: 'Download from Desktop',
    speed: '64 MBps',
    eta: '00:09',
    totalSize: '640 MB',
    progress: 86,
  },
];

const statusText = computed(() => {
  if (activeTab.value === 'transfer') {
    return '4 active connections';
  }
  if (activeTab.value === 'receive') {
    return receiveToken.value ? 'Ready to connect with short token' : 'Waiting for sender';
  }
  if (activeTab.value === 'send') {
    return inviteInput.value || sendToken.value ? 'Pairing details entered' : 'Choose scan or paste';
  }
  return concurrentTransfers.value ? 'Concurrent mode' : 'Sequential mode';
});

function flash(message: string) {
  toast.value = message;
  window.setTimeout(() => {
    if (toast.value === message) {
      toast.value = '';
    }
  }, 1800);
}

async function copyInvite() {
  await navigator.clipboard?.writeText(demoLink);
  copied.value = true;
  flash('Invite link copied');
  window.setTimeout(() => {
    copied.value = false;
  }, 1500);
}

async function pasteInvite() {
  inviteInput.value = (await navigator.clipboard?.readText()) || demoInvite;
  flash('Invite link pasted');
}

function onCameraPick(event: Event) {
  const input = event.target as HTMLInputElement;
  selectedImage.value = input.files?.[0]?.name ?? '';
  flash(selectedImage.value ? `Selected ${selectedImage.value}` : 'Camera import ready');
}

function onFilePick(event: Event) {
  const input = event.target as HTMLInputElement;
  selectedFile.value = input.files?.[0]?.name ?? '';
  flash(selectedFile.value ? `Selected ${selectedFile.value}` : 'File selection ready');
}
</script>

<template>
  <section class="mobile-stage">
    <div class="phone-frame">
      <div class="phone-screen">
        <div class="android-status">
          <span>10:24</span>
          <span>5G 84%</span>
        </div>
        <header class="mobile-header">
          <div>
            <p class="eyebrow">Android pairing</p>
            <h2>Envoix</h2>
          </div>
          <span class="status-pill">{{ statusText }}</span>
        </header>

        <section v-if="activeTab === 'transfer'" class="mobile-content transfer-content">
          <article v-for="connection in connections" :key="connection.peer" class="connection-card">
            <div class="connection-head">
              <div>
                <strong>{{ connection.direction }}</strong>
                <span>{{ connection.peer }}</span>
              </div>
              <span class="mode-pill">{{ connection.mode }}</span>
            </div>
            <div class="progress-track" :aria-label="`${connection.progress}% complete`">
              <span :style="{ width: `${connection.progress}%` }"></span>
            </div>
            <div class="transfer-meta">
              <span>{{ connection.speed }}</span>
              <span>{{ connection.eta }} ETA</span>
              <span>{{ connection.totalSize }}</span>
            </div>
          </article>
        </section>

        <section v-else-if="activeTab === 'receive'" class="mobile-content">
          <DemoQr :value="demoLink" label="Receive invite QR code" :size="184" />
          <div class="link-row">
            <span>{{ demoLink }}</span>
            <CopyButton :copied="copied" @copy="copyInvite" />
          </div>
          <div class="form-block">
            <label for="receive-token">Short token pairing</label>
            <input id="receive-token" v-model="receiveToken" autocomplete="off" placeholder="shared-token-123" />
            <button class="primary-action" type="button" @click="flash('Receiver pairing request sent')">
              <Zap :size="18" aria-hidden="true" />
              Connect
            </button>
          </div>
        </section>

        <section v-else-if="activeTab === 'send'" class="mobile-content">
          <label class="camera-button">
            <Camera :size="22" aria-hidden="true" />
            <span>{{ selectedImage || 'Scan or import QR' }}</span>
            <input type="file" accept="image/*" capture="environment" @change="onCameraPick" />
          </label>
          <label class="file-drop small">
            <FileUp :size="22" aria-hidden="true" />
            <span>{{ selectedFile || 'Select file' }}</span>
            <input type="file" @change="onFilePick" />
          </label>
          <div class="input-with-action">
            <input v-model="inviteInput" placeholder="Paste invite link" />
            <button type="button" @click="pasteInvite">
              <Clipboard :size="16" aria-hidden="true" />
              Paste
            </button>
          </div>
          <div class="form-block">
            <label for="send-token">Short token pairing</label>
            <input id="send-token" v-model="sendToken" autocomplete="off" placeholder="shared-token-123" />
            <button class="primary-action" type="button" @click="flash('Sender pairing request sent')">
              <Zap :size="18" aria-hidden="true" />
              Connect
            </button>
          </div>
        </section>

        <section v-else class="mobile-content">
          <button class="setting-toggle" type="button" @click="concurrentTransfers = !concurrentTransfers">
            <span>Concurrent transferring</span>
            <strong>{{ concurrentTransfers ? 'On' : 'Off' }}</strong>
          </button>
          <label class="field-row">
            Server URL
            <input v-model="serverUrl" />
          </label>
          <label class="field-row">
            Relay URL
            <input v-model="relayUrl" />
          </label>
          <label class="field-row">
            Speed limit
            <span class="number-row">
              <input v-model.number="speedLimit" type="number" min="1" max="1000" />
              <span>MBps</span>
            </span>
          </label>
        </section>

        <nav class="bottom-tabs" aria-label="Mobile workflow tabs">
          <button
            v-for="tab in tabs"
            :key="tab.id"
            type="button"
            :class="{ active: activeTab === tab.id }"
            @click="activeTab = tab.id"
          >
            <component :is="tab.icon" :size="20" aria-hidden="true" />
            <span>{{ tab.label }}</span>
          </button>
        </nav>
        <Transition name="toast">
          <p v-if="toast" class="toast">{{ toast }}</p>
        </Transition>
      </div>
    </div>
  </section>
</template>
