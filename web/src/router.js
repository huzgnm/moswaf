import { createRouter, createWebHashHistory } from 'vue-router'
import { session } from './api'

import Login    from './views/Login.vue'
import Overview from './views/Overview.vue'
import Sites    from './views/Sites.vue'
import Rules    from './views/Rules.vue'
import Events   from './views/Events.vue'
import IPLists  from './views/IPLists.vue'
import Settings from './views/Settings.vue'

// Hash history: the dashboard can be served from any path without
// needing rewrite rules on the server side.
const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/login',    component: Login,    meta: { public: true, title: 'Sign in' } },
    { path: '/',         component: Overview, meta: { title: 'Overview' } },
    { path: '/sites',    component: Sites,    meta: { title: 'Sites' } },
    { path: '/rules',    component: Rules,    meta: { title: 'Detection rules' } },
    { path: '/events',   component: Events,   meta: { title: 'Attack log' } },
    { path: '/ips',      component: IPLists,  meta: { title: 'IP lists' } },
    { path: '/settings', component: Settings, meta: { title: 'Settings' } },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  if (!to.meta.public && !session.token) return '/login'
  if (to.path === '/login' && session.token) return '/'
  return true
})

export default router
