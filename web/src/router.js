import { createRouter, createWebHashHistory } from 'vue-router'
import { session } from './api'

import Login     from './views/Login.vue'
import Overview  from './views/Overview.vue'
import Sites     from './views/Sites.vue'
import Rules     from './views/Rules.vue'
import Events    from './views/Events.vue'
import IPLists   from './views/IPLists.vue'
import RateLimit from './views/RateLimit.vue'
import Settings  from './views/Settings.vue'

// Hash history: the dashboard can be served from any path without
// needing rewrite rules on the server side.
const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/login',     component: Login,     meta: { public: true, title: 'login.title' } },
    { path: '/',          component: Overview,  meta: { title: 'nav.overview' } },
    { path: '/sites',     component: Sites,     meta: { title: 'nav.sites' } },
    { path: '/rules',     component: Rules,     meta: { title: 'nav.rules' } },
    { path: '/events',    component: Events,    meta: { title: 'nav.events' } },
    { path: '/ips',       component: IPLists,   meta: { title: 'nav.ips' } },
    { path: '/ratelimit', component: RateLimit, meta: { title: 'nav.ratelimit' } },
    { path: '/settings',  component: Settings,  meta: { title: 'nav.settings' } },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  if (!to.meta.public && !session.token) return '/login'
  if (to.path === '/login' && session.token) return '/'
  return true
})

export default router
