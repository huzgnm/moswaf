<script setup>
import { ref, watch, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, session, toast, notify, logout, fmtShortTime } from './api'
import { t } from './i18n'
import { ui } from './ui'
import LanguagePicker from './components/LanguagePicker.vue'
import Icon from './components/Icon.vue'
import Logo from './components/Logo.vue'
import Modal from './components/Modal.vue'

const route = useRoute()
const router = useRouter()

// label is a translation key; the sidebar resolves it at render time so the menu
// follows the language without this list being rebuilt.
const NAV = [
  { section: 'nav.sectionMonitor' },
  { path: '/',          label: 'nav.overview',  icon: 'overview' },
  { path: '/events',    label: 'nav.events',    icon: 'events' },
  { section: 'nav.sectionProtect' },
  { path: '/sites',     label: 'nav.sites',     icon: 'sites' },
  { path: '/rules',     label: 'nav.rules',     icon: 'rules' },
  { path: '/ips',       label: 'nav.ips',       icon: 'ips' },
  { path: '/ratelimit', label: 'nav.ratelimit', icon: 'ratelimit' },
  { section: 'nav.sectionSystem' },
  { path: '/settings',  label: 'nav.settings',  icon: 'settings' },
]

const underAttack = ref(false)
const busy = ref(false)
const confirmAttack = ref(false)
const status = ref(null)
const isLogin = computed(() => route.path === '/login')
let statusTimer = null

async function loadContext() {
  if (!session.token) return
  try {
    const [me, settings] = await Promise.all([
      api.get('/api/auth/me'),
      api.get('/api/settings'),
    ])
    session.user = me
    underAttack.value = settings.under_attack
  } catch (e) {
    /* requireAuth already redirects to the sign-in page on a bad token */
  }
  loadStatus()
}

// The protection pill needs to know whether the data plane is answering. It is
// polled lightly here so every page shows the same truth, not only Overview.
async function loadStatus() {
  if (!session.token) return
  try {
    status.value = await api.get('/api/system/status')
  } catch (e) {
    status.value = null
  }
}

const dataplaneOk = computed(() => {
  const d = status.value?.dataplane
  return d && typeof d === 'object' && d.status === 'ok'
})

// One of three states, in priority order: an attack in progress beats everything,
// a data plane that is not answering beats "fine".
const protection = computed(() => {
  if (underAttack.value) return { tone: 'attack', text: t('app.pillAttack') }
  if (status.value && !dataplaneOk.value) return { tone: 'warn', text: t('app.pillDataplane') }
  if (status.value) return { tone: 'ok', text: t('app.pillOk') }
  return { tone: '', text: t('app.pillUnknown') }
})

function askUnderAttack() {
  confirmAttack.value = true
}

async function toggleUnderAttack() {
  const next = !underAttack.value
  busy.value = true
  try {
    await api.post('/api/settings/under-attack', { enabled: next })
    underAttack.value = next
    confirmAttack.value = false
    notify(t(next ? 'app.underAttackOn' : 'app.underAttackOff'))
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

// Other views (Settings) can flip the same flag; keep the pill honest
watch(() => session.token, loadContext, { immediate: true })
watch(() => route.path, () => { ui.sidebarOpen = false; loadStatus() })

function doLogout() {
  logout()
  router.push('/login')
}

function onKey(e) {
  if (e.key === 'Escape' && ui.sidebarOpen) ui.sidebarOpen = false
}

onMounted(() => {
  document.addEventListener('keydown', onKey)
  statusTimer = setInterval(loadStatus, 30000)
})
onUnmounted(() => {
  document.removeEventListener('keydown', onKey)
  clearInterval(statusTimer)
})

const initials = computed(() => (session.user?.username || '?').slice(0, 1).toUpperCase())
</script>

<template>
  <router-view v-if="isLogin" />

  <div v-else class="layout">
    <div v-if="ui.sidebarOpen" class="drawer-backdrop" @click="ui.sidebarOpen = false"></div>

    <aside class="sidebar" :class="{ collapsed: ui.sidebarCollapsed, open: ui.sidebarOpen }" :aria-label="t('nav.aria')">
      <div class="brand-row">
        <Logo :size="30" />
        <div class="brand-text">
          <div class="wordmark">MosWAF</div>
          <div class="wordmark-sub">{{ t('app.brandSub') }}</div>
        </div>
      </div>

      <nav :aria-label="t('nav.aria')">
        <template v-for="item in NAV" :key="item.path || item.section">
          <div v-if="item.section" class="nav-section">{{ t(item.section) }}</div>
          <router-link
            v-else
            :to="item.path" class="nav-item"
            :class="{ active: route.path === item.path }"
            :aria-current="route.path === item.path ? 'page' : null"
            :title="ui.sidebarCollapsed ? t(item.label) : null"
          >
            <Icon :name="item.icon" />
            <span class="nav-label">{{ t(item.label) }}</span>
          </router-link>
        </template>
      </nav>

      <div class="sidebar-foot">
        <div class="user-chip" :title="session.user?.username">
          <span class="avatar" aria-hidden="true">{{ initials }}</span>
          <span class="user-name">{{ session.user?.username }}</span>
        </div>
        <button type="button" class="nav-item" :title="ui.sidebarCollapsed ? t('nav.signOut') : null" @click="doLogout">
          <Icon name="signout" />
          <span class="nav-label">{{ t('nav.signOut') }}</span>
        </button>
        <button
          type="button" class="nav-item collapse-btn"
          :aria-label="ui.sidebarCollapsed ? t('nav.expand') : t('nav.collapse')"
          :title="ui.sidebarCollapsed ? t('nav.expand') : t('nav.collapse')"
          @click="ui.sidebarCollapsed = !ui.sidebarCollapsed"
        >
          <Icon :name="ui.sidebarCollapsed ? 'expand' : 'collapse'" />
          <span class="nav-label">{{ t('nav.collapse') }}</span>
        </button>
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <div class="topbar-left">
          <button type="button" class="icon-btn menu-btn" :aria-label="t('nav.menu')" @click="ui.sidebarOpen = true">
            <Icon name="menu" />
          </button>
          <h1>{{ t(route.meta.title) }}</h1>
          <div v-if="ui.scope || ui.updatedAt" class="scope">
            <span v-if="ui.scope">{{ ui.scope }}</span>
            <span v-if="ui.updatedAt" class="dotsep"></span>
            <span v-if="ui.updatedAt">{{ t('app.updatedAt', { time: fmtShortTime(ui.updatedAt) }) }}</span>
          </div>
        </div>

        <div class="topbar-right">
          <span class="status-pill" :class="protection.tone" :title="protection.text">
            <span class="pulse"></span>
            <span class="pill-text">{{ protection.text }}</span>
          </span>

          <button
            type="button" class="btn btn-sm" :class="underAttack ? 'btn-danger solid' : ''"
            :title="t('app.underAttackHint')" :disabled="busy"
            @click="askUnderAttack"
          >
            <Icon name="zap" />
            <span class="ua-text">{{ underAttack ? t('app.underAttackStop') : t('app.underAttack') }}</span>
          </button>

          <LanguagePicker />
        </div>
      </header>

      <main class="content">
        <router-view />
      </main>
    </div>
  </div>

  <Modal
    v-if="confirmAttack"
    narrow
    :title="underAttack ? t('app.confirmOffTitle') : t('app.confirmOnTitle')"
    :ok-label="underAttack ? t('app.underAttackStop') : t('app.underAttackStart')"
    :danger="!underAttack"
    :busy="busy"
    @close="confirmAttack = false"
    @submit="toggleUnderAttack"
  >
    <p class="confirm-text">{{ underAttack ? t('app.confirmOffBody') : t('app.confirmOnBody') }}</p>
    <div v-if="!underAttack" class="alert alert-warn">
      <Icon name="alert" />
      <div class="alert-body">{{ t('app.confirmOnImpact') }}</div>
    </div>
  </Modal>

  <div v-if="toast.text" class="toast" :class="{ error: toast.error }" :key="toast.seq" role="status">
    {{ toast.text }}
  </div>
</template>

<style scoped>
.confirm-text { margin: 0 0 14px; color: var(--ink-2); line-height: 1.55; }
@media (max-width: 600px) { .ua-text { display: none; } }
</style>
