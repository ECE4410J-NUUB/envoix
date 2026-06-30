import { createRouter, createWebHistory } from 'vue-router';

import CliDemo from './views/CliDemo.vue';
import GuiDemo from './views/GuiDemo.vue';
import MobileDemo from './views/MobileDemo.vue';

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/demo/mobile' },
    { path: '/demo/mobile', name: 'mobile', component: MobileDemo },
    { path: '/demo/cli', name: 'cli', component: CliDemo },
    { path: '/demo/gui', name: 'gui', component: GuiDemo },
  ],
});
