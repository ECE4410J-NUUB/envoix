<script setup lang="ts">
import { computed, ref, watchEffect } from 'vue';
import { Monitor, Moon, Smartphone, Sun, TerminalSquare } from '@lucide/vue';
import { RouterLink, RouterView, useRoute } from 'vue-router';

const route = useRoute();
const darkMode = ref(window.matchMedia('(prefers-color-scheme: dark)').matches);

const navItems = [
  { path: '/demo/mobile', label: 'Mobile', icon: Smartphone },
  { path: '/demo/cli', label: 'CLI', icon: TerminalSquare },
  { path: '/demo/gui', label: 'GUI', icon: Monitor },
];

const pageTitle = computed(() => {
  const current = navItems.find((item) => item.path === route.path);
  return current ? `${current.label} workflow` : 'UI/UX demo';
});

watchEffect(() => {
  document.documentElement.dataset.theme = darkMode.value ? 'dark' : 'light';
});
</script>

<template>
  <div class="app-shell">
    <header class="top-bar">
      <div>
        <p class="eyebrow">Envoix demo</p>
        <h1>{{ pageTitle }}</h1>
      </div>
      <nav class="main-nav" aria-label="Demo routes">
        <RouterLink v-for="item in navItems" :key="item.path" :to="item.path">
          <component :is="item.icon" :size="18" aria-hidden="true" />
          <span>{{ item.label }}</span>
        </RouterLink>
      </nav>
      <button class="icon-button theme-toggle" type="button" @click="darkMode = !darkMode">
        <Sun v-if="darkMode" :size="18" aria-hidden="true" />
        <Moon v-else :size="18" aria-hidden="true" />
        <span>{{ darkMode ? 'Light' : 'Dark' }}</span>
      </button>
    </header>
    <main>
      <RouterView />
    </main>
  </div>
</template>
