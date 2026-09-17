import { createRouter, createWebHashHistory } from 'vue-router'
import { session } from './api'

import Login    from './views/Login.vue'
import Overview from './views/Overview.vue'
import Sites    from './views/Sites.vue'
import Rules    from './views/Rules.vue'
import Events   from './views/Events.vue'
import IPLists  from './views/IPLists.vue'
import Settings from './views/Settings.vue'

// Dung hash history: dashboard co the phuc vu tu bat ky duong dan nao
// ma khong can cau hinh rewrite phia server.
const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/login',    component: Login,    meta: { public: true, title: 'Dang nhap' } },
    { path: '/',         component: Overview, meta: { title: 'Tong quan' } },
    { path: '/sites',    component: Sites,    meta: { title: 'Trang web' } },
    { path: '/rules',    component: Rules,    meta: { title: 'Luat phat hien' } },
    { path: '/events',   component: Events,   meta: { title: 'Nhat ky tan cong' } },
    { path: '/ips',      component: IPLists,  meta: { title: 'Danh sach IP' } },
    { path: '/settings', component: Settings, meta: { title: 'Cai dat' } },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  if (!to.meta.public && !session.token) return '/login'
  if (to.path === '/login' && session.token) return '/'
  return true
})

export default router
