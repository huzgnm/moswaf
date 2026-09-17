<script setup>
import { ref, watch, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, session, toast, notify, logout } from './api'

const route = useRoute()
const router = useRouter()

const nav = [
  { path: '/',         label: 'Overview' },
  { path: '/sites',    label: 'Sites' },
  { path: '/events',   label: 'Attack log' },
  { path: '/rules',    label: 'Detection rules' },
  { path: '/ips',      label: 'IP lists' },
  { path: '/settings', label: 'Settings' },
]

const underAttack = ref(false)
const busy = ref(false)
const isLogin = computed(() => route.path === '/login')

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
}

async function toggleUnderAttack() {
  const next = !underAttack.value
  busy.value = true
  try {
    await api.post('/api/settings/under-attack', { enabled: next })
    underAttack.value = next
    notify(next
      ? 'Under-attack mode on: every unknown visitor must pass the JS challenge'
      : 'Under-attack mode off')
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

watch(() => session.token, loadContext, { immediate: true })

function doLogout() {
  logout()
  router.push('/login')
}
</script>

<template>
  <router-view v-if="isLogin" />

  <div v-else class="layout">
    <aside class="sidebar">
      <div class="brand">Mos<b>WAF</b></div>
      <div
        v-for="item in nav"
        :key="item.path"
        class="nav-item"
        :class="{ active: route.path === item.path }"
        @click="router.push(item.path)"
      >
        <span class="dot"></span>{{ item.label }}
      </div>
      <div class="spacer"></div>
      <div class="nav-item" @click="doLogout">
        <span class="dot"></span>Sign out
      </div>
    </aside>

    <div class="main">
      <header class="topbar">
        <h1 style="font-size:15px">{{ route.meta.title }}</h1>
        <div class="row">
          <label class="switch danger" :title="'Force every visitor to solve a JS challenge'">
            <input type="checkbox" :checked="underAttack" :disabled="busy" @change="toggleUnderAttack" />
            <span class="track"></span>
            <span :style="{ color: underAttack ? 'var(--critical)' : 'var(--text-secondary)' }">
              Under-attack mode
            </span>
          </label>
          <span class="card-sub">{{ session.user?.username }}</span>
        </div>
      </header>

      <main class="content">
        <router-view />
      </main>
    </div>
  </div>

  <div v-if="toast.text" class="toast" :class="{ error: toast.error }" :key="toast.seq">
    {{ toast.text }}
  </div>
</template>
