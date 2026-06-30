<script setup lang="ts">
import { ref } from 'vue';
import { Clipboard, Download, FileUp, FolderOpen, Link, QrCode, Send } from '@lucide/vue';

import CopyButton from '@/components/CopyButton.vue';
import DemoQr from '@/components/DemoQr.vue';
import { demoInvite, demoLink } from '@/data/demo';

type GuiSection = 'send' | 'receive' | 'pairing';

const activeSection = ref<GuiSection>('send');
const inviteInput = ref(demoInvite);
const selectedFile = ref('design-review.pdf');
const saveAs = ref('Downloads/envoix');
const receiverToken = ref('');
const senderToken = ref('');
const copied = ref(false);
const activity = ref('Ready');

function selectSection(section: GuiSection) {
  activeSection.value = section;
  activity.value = `${section[0].toUpperCase()}${section.slice(1)} view`;
}

function chooseFile(event: Event) {
  const input = event.target as HTMLInputElement;
  selectedFile.value = input.files?.[0]?.name ?? selectedFile.value;
  activity.value = `Selected ${selectedFile.value}`;
}

function importQr(event: Event) {
  const input = event.target as HTMLInputElement;
  const fileName = input.files?.[0]?.name ?? 'QR image';
  inviteInput.value = demoInvite;
  activity.value = `Imported ${fileName}`;
}

async function copyInvite() {
  await navigator.clipboard?.writeText(demoLink);
  copied.value = true;
  activity.value = 'Invite copied';
  window.setTimeout(() => {
    copied.value = false;
  }, 1400);
}

async function pasteInvite() {
  inviteInput.value = (await navigator.clipboard?.readText()) || demoInvite;
  activity.value = 'Invite pasted';
}

function connectPairing() {
  activity.value = receiverToken.value || senderToken.value ? 'Pairing request sent' : 'Enter a short token';
}
</script>

<template>
  <section class="gui-page">
    <div class="desktop-window">
      <aside class="side-rail">
        <strong>Envoix</strong>
        <button
          class="rail-button"
          :class="{ active: activeSection === 'send' }"
          type="button"
          @click="selectSection('send')"
        >
          <Send :size="18" aria-hidden="true" /> Send
        </button>
        <button
          class="rail-button"
          :class="{ active: activeSection === 'receive' }"
          type="button"
          @click="selectSection('receive')"
        >
          <Download :size="18" aria-hidden="true" /> Receive
        </button>
        <button
          class="rail-button"
          :class="{ active: activeSection === 'pairing' }"
          type="button"
          @click="selectSection('pairing')"
        >
          <QrCode :size="18" aria-hidden="true" /> Pairing
        </button>
      </aside>

      <main class="desktop-main">
        <div class="desktop-toolbar">
          <div>
            <p class="eyebrow">Desktop GUI</p>
            <h2>Transfer setup</h2>
          </div>
          <span class="status-pill">{{ activity }}</span>
        </div>

        <div class="gui-grid">
          <section v-if="activeSection === 'receive'" class="tool-panel wide">
            <h3>Receive</h3>
            <DemoQr :value="demoLink" label="Desktop receive invite QR code" :size="168" />
            <div class="link-row compact">
              <span>{{ demoLink }}</span>
              <CopyButton :copied="copied" @copy="copyInvite" />
            </div>
            <label class="field-row">
              Save as
              <span class="input-with-action">
                <input v-model="saveAs" />
                <button type="button" @click="activity = 'Save location selected'">
                  <FolderOpen :size="16" aria-hidden="true" />
                  Select
                </button>
              </span>
            </label>
            <button class="primary-action" type="button" @click="activity = 'Receiver waiting for sender'">
              <Download :size="18" aria-hidden="true" />
              Start receive
            </button>
          </section>

          <section v-else-if="activeSection === 'send'" class="tool-panel wide">
            <h3>Send</h3>
            <label class="file-drop">
              <FileUp :size="24" aria-hidden="true" />
              <span>{{ selectedFile }}</span>
              <input type="file" @change="chooseFile" />
            </label>
            <label class="field-row">
              Invite link
              <span class="input-with-action">
                <input v-model="inviteInput" />
                <button type="button" @click="pasteInvite">
                  <Clipboard :size="16" aria-hidden="true" />
                  Paste
                </button>
              </span>
            </label>
            <label class="file-drop small">
              <QrCode :size="22" aria-hidden="true" />
              <span>Import QR</span>
              <input type="file" accept="image/*" @change="importQr" />
            </label>
            <button class="primary-action" type="button" @click="activity = 'Sender connecting with invite'">
              <Send :size="18" aria-hidden="true" />
              Start send
            </button>
          </section>

          <section v-else class="tool-panel wide">
            <h3>Short token pairing</h3>
            <div class="pairing-row">
              <label>
                Receiver token
                <input v-model="receiverToken" placeholder="shared-token-123" />
              </label>
              <label>
                Sender token
                <input v-model="senderToken" placeholder="shared-token-123" />
              </label>
              <button class="primary-action" type="button" @click="connectPairing">
                <Link :size="18" aria-hidden="true" />
                Connect
              </button>
            </div>
          </section>
        </div>
      </main>
    </div>
  </section>
</template>
