<script setup>
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { api, notify, fmtNumber } from '../api'
import { t } from '../i18n'
import Modal from '../components/Modal.vue'
import Icon from '../components/Icon.vue'

// Rate limiting, the way an operator thinks about it: three rules, each a
// switch and one sentence saying what it does with the current numbers, and
// underneath the addresses those rules are holding back right now.
//
// The numbers live in /api/settings (same fields as before, nothing new); the
// live list is /api/bans, which the control plane proxies from the data plane's
// shared memory. A rule is "off" when its threshold is 0 - that is what the
// engine checks (ratelimit.lua: `rps > 0`, flood.lua: `flood_rps ... or 0`).

const settings = ref(null)
const bans = ref([])
const loading = ref(true)
const busy = ref(false)
const editing = ref('')     // 'access' | 'flood' | 'error'
const form = ref({})
let timer = null

// Values to restore when a rule is switched back on after being zeroed
const DEFAULTS = { global_rate_rps: 60, global_rate_burst: 120, flood_rps: 300, flood_error_rate: 30 }
const remembered = {}

async function load(first = false) {
  if (first) loading.value = true
  try {
    const [st, b] = await Promise.all([api.get('/api/settings'), api.get('/api/bans')])
    settings.value = st
    bans.value = b.items || []
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

async function save(patch) {
  busy.value = true
  try {
    settings.value = await api.put('/api/settings', { ...settings.value, ...patch })
    notify(t('settings.saved'))
    editing.value = ''
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

const accessOn = computed(() => settings.value && settings.value.global_rate_rps > 0)
const floodOn = computed(() => settings.value && settings.value.flood_rps > 0)
const errorOn = computed(() => settings.value && settings.value.flood_error_rate > 0)

function toggleAccess(on) {
  if (!on) {
    remembered.global_rate_rps = settings.value.global_rate_rps
    remembered.global_rate_burst = settings.value.global_rate_burst
    return save({ global_rate_rps: 0, global_rate_burst: 0 })
  }
  return save({
    global_rate_rps: remembered.global_rate_rps || DEFAULTS.global_rate_rps,
    global_rate_burst: remembered.global_rate_burst || DEFAULTS.global_rate_burst,
  })
}
function toggleFlood(on) {
  if (!on) { remembered.flood_rps = settings.value.flood_rps; return save({ flood_rps: 0 }) }
  return save({ flood_rps: remembered.flood_rps || DEFAULTS.flood_rps })
}
function toggleError(on) {
  if (!on) { remembered.flood_error_rate = settings.value.flood_error_rate; return save({ flood_error_rate: 0 }) }
  return save({ flood_error_rate: remembered.flood_error_rate || DEFAULTS.flood_error_rate })
}

function openEdit(which) {
  const s = settings.value
  editing.value = which
  form.value = which === 'access'
    ? { global_rate_rps: s.global_rate_rps || DEFAULTS.global_rate_rps, global_rate_burst: s.global_rate_burst || DEFAULTS.global_rate_burst, ban_seconds: s.ban_seconds }
    : which === 'flood'
      ? { flood_rps: s.flood_rps || DEFAULTS.flood_rps, flood_hold: s.flood_hold }
      : { flood_error_rate: s.flood_error_rate || DEFAULTS.flood_error_rate, flood_hold: s.flood_hold }
}

function submitEdit() {
  const f = form.value
  const patch = {}
  for (const k of Object.keys(f)) patch[k] = Number(f[k]) || 0
  return save(patch)
}

// The sentence for each rule, built from the live numbers
const accessSentence = computed(() => {
  const s = settings.value
  if (!s) return ''
  return accessOn.value
    ? t('ratelimit.access.on', { rps: s.global_rate_rps, burst: s.global_rate_burst, ban: fmtNumber(s.ban_seconds) })
    : t('ratelimit.access.off')
})
const floodSentence = computed(() => {
  const s = settings.value
  if (!s) return ''
  return floodOn.value ? t('ratelimit.flood.on', { rps: fmtNumber(s.flood_rps), hold: fmtNumber(s.flood_hold) }) : t('ratelimit.flood.off')
})
const errorSentence = computed(() => {
  const s = settings.value
  if (!s) return ''
  return errorOn.value ? t('ratelimit.error.on', { percent: s.flood_error_rate, hold: fmtNumber(s.flood_hold) }) : t('ratelimit.error.off')
})

// ---------------------------------------------------------------- bans

async function unban(ip) {
  try {
    await api.del(`/api/bans/${encodeURIComponent(ip)}`)
    notify(ip === '*' ? t('ips.allLifted') : t('ips.lifted', { ip }))
    await load()
  } catch (e) {
    notify(e.message, true)
  }
}

function fmtTTL(sec) {
  if (sec <= 0) return t('ips.ttl.expiring')
  const m = Math.floor(sec / 60)
  return m > 0 ? t('ips.ttl.minutes', { m, s: Math.floor(sec % 60) }) : t('ips.ttl.seconds', { s: Math.floor(sec) })
}

function reasonLabel(reason) {
  const key = `ratelimit.reason.${reason}`
  const label = t(key)
  return label === key ? reason : label
}

onMounted(() => {
  load(true)
  timer = setInterval(() => load(false), 10000)
})
onUnmounted(() => clearInterval(timer))
</script>

<template>
  <div class="page-head">
    <div>
      <h2>{{ t('ratelimit.title') }}</h2>
      <p class="page-sub">{{ t('ratelimit.sub') }}</p>
    </div>
  </div>

  <div class="grid grid-3 rules">
    <!-- per-IP -->
    <div class="card rule-card" :class="{ on: accessOn }">
      <div class="rule-head">
        <div class="rule-title"><Icon name="clock" />{{ t('ratelimit.access.title') }}</div>
        <label class="switch" :class="{ 'is-disabled': !settings || busy }">
          <input type="checkbox" :checked="accessOn" :disabled="!settings || busy" @change="toggleAccess($event.target.checked)" />
          <span class="track"></span>
          <span class="sr-only">{{ t('ratelimit.access.title') }}</span>
        </label>
      </div>
      <p class="rule-text" :class="{ skel: loading }">{{ accessSentence }}</p>
      <div class="rule-foot">
        <span class="tag" :class="accessOn ? 'tag-ok' : 'tag-off'"><span class="dot"></span>{{ accessOn ? t('ratelimit.enabled') : t('ratelimit.disabled') }}</span>
        <button type="button" class="btn btn-sm" :disabled="!settings" @click="openEdit('access')"><Icon name="edit" />{{ t('common.edit') }}</button>
      </div>
    </div>

    <!-- flood -->
    <div class="card rule-card" :class="{ on: floodOn }">
      <div class="rule-head">
        <div class="rule-title"><Icon name="zap" />{{ t('ratelimit.flood.title') }}</div>
        <label class="switch" :class="{ 'is-disabled': !settings || busy }">
          <input type="checkbox" :checked="floodOn" :disabled="!settings || busy" @change="toggleFlood($event.target.checked)" />
          <span class="track"></span>
          <span class="sr-only">{{ t('ratelimit.flood.title') }}</span>
        </label>
      </div>
      <p class="rule-text" :class="{ skel: loading }">{{ floodSentence }}</p>
      <div class="rule-foot">
        <span class="tag" :class="floodOn ? 'tag-ok' : 'tag-off'"><span class="dot"></span>{{ floodOn ? t('ratelimit.enabled') : t('ratelimit.disabled') }}</span>
        <button type="button" class="btn btn-sm" :disabled="!settings" @click="openEdit('flood')"><Icon name="edit" />{{ t('common.edit') }}</button>
      </div>
    </div>

    <!-- origin errors -->
    <div class="card rule-card" :class="{ on: errorOn }">
      <div class="rule-head">
        <div class="rule-title"><Icon name="alert" />{{ t('ratelimit.error.title') }}</div>
        <label class="switch" :class="{ 'is-disabled': !settings || busy }">
          <input type="checkbox" :checked="errorOn" :disabled="!settings || busy" @change="toggleError($event.target.checked)" />
          <span class="track"></span>
          <span class="sr-only">{{ t('ratelimit.error.title') }}</span>
        </label>
      </div>
      <p class="rule-text" :class="{ skel: loading }">{{ errorSentence }}</p>
      <div class="rule-foot">
        <span class="tag" :class="errorOn ? 'tag-ok' : 'tag-off'"><span class="dot"></span>{{ errorOn ? t('ratelimit.enabled') : t('ratelimit.disabled') }}</span>
        <button type="button" class="btn btn-sm" :disabled="!settings" @click="openEdit('error')"><Icon name="edit" />{{ t('common.edit') }}</button>
      </div>
    </div>
  </div>

  <div class="alert alert-info">
    <Icon name="info" />
    <div class="alert-body">{{ t('ratelimit.perSiteNote') }} <router-link to="/sites">{{ t('nav.sites') }}</router-link></div>
  </div>

  <!-- currently limited -->
  <div class="card">
    <div class="card-head">
      <div>
        <div class="card-title">{{ t('ratelimit.bans.title') }}</div>
        <div class="card-sub">{{ t('ratelimit.bans.sub') }}</div>
      </div>
      <button type="button" class="btn btn-sm btn-danger" :disabled="!bans.length" @click="unban('*')">{{ t('ips.liftAll') }}</button>
    </div>

    <div v-if="loading" class="skel-list"><div v-for="i in 3" :key="i" class="skel skel-line"></div></div>
    <div v-else-if="!bans.length" class="empty">
      <Icon name="shieldOk" />
      <b>{{ t('ips.noBans') }}</b>
      <span class="empty-hint">{{ t('ratelimit.bans.emptyHint') }}</span>
    </div>
    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('ips.col.ip') }}</th>
            <th>{{ t('ips.col.reason') }}</th>
            <th>{{ t('ratelimit.bans.action') }}</th>
            <th>{{ t('ips.col.timeLeft') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in bans" :key="b.ip">
            <td class="mono">{{ b.ip }}</td>
            <td><span class="tag tag-deny"><span class="dot"></span>{{ reasonLabel(b.reason) }}</span></td>
            <td class="sub">{{ t('ratelimit.bans.blockedFor', { seconds: fmtNumber(settings?.ban_seconds ?? 0) }) }}</td>
            <td class="sub nowrap">{{ fmtTTL(b.ttl) }}</td>
            <td class="actions">
              <button type="button" class="btn btn-sm" @click="unban(b.ip)">{{ t('ips.liftBan') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>

  <Modal
    v-if="editing"
    narrow
    :title="t(`ratelimit.${editing}.title`)"
    :busy="busy"
    @close="editing = ''"
    @submit="submitEdit"
  >
    <template v-if="editing === 'access'">
      <div class="field">
        <label class="label">{{ t('settings.rps') }}</label>
        <input v-model="form.global_rate_rps" type="number" min="1" class="input mono" />
      </div>
      <div class="field">
        <label class="label">{{ t('settings.burst') }}</label>
        <input v-model="form.global_rate_burst" type="number" min="1" class="input mono" />
        <div class="hint">{{ t('settings.burstHint') }}</div>
      </div>
      <div class="field">
        <label class="label">{{ t('settings.banSeconds') }}</label>
        <input v-model="form.ban_seconds" type="number" min="10" class="input mono" />
        <div class="hint">{{ t('settings.banSecondsHint') }}</div>
      </div>
    </template>
    <template v-else-if="editing === 'flood'">
      <div class="field">
        <label class="label">{{ t('settings.floodRPS') }}</label>
        <input v-model="form.flood_rps" type="number" min="1" class="input mono" />
        <div class="hint">{{ t('settings.floodRPSHint') }}</div>
      </div>
      <div class="field">
        <label class="label">{{ t('settings.floodHold') }}</label>
        <input v-model="form.flood_hold" type="number" min="10" class="input mono" />
        <div class="hint">{{ t('settings.floodHoldHint') }}</div>
      </div>
    </template>
    <template v-else>
      <div class="field">
        <label class="label">{{ t('settings.floodErrorRate') }}</label>
        <input v-model="form.flood_error_rate" type="number" min="1" max="100" class="input mono" />
        <div class="hint">{{ t('settings.floodErrorRateHint') }}</div>
      </div>
      <div class="field">
        <label class="label">{{ t('settings.floodHold') }}</label>
        <input v-model="form.flood_hold" type="number" min="10" class="input mono" />
        <div class="hint">{{ t('settings.floodHoldHint') }}</div>
      </div>
    </template>
  </Modal>
</template>

<style scoped>
.rules { align-items: stretch; }
.rule-card { display: flex; flex-direction: column; gap: 12px; border-top: 2px solid var(--line-2); }
.rule-card.on { border-top-color: var(--ink); }
.rule-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.rule-title { display: inline-flex; align-items: center; gap: 9px; font-weight: 600; font-size: 14px; }
.rule-title .ico { width: 17px; height: 17px; color: var(--ink-3); }
.rule-card.on .rule-title .ico { color: var(--ink); }
.rule-text { margin: 0; color: var(--ink-2); font-size: 13px; line-height: 1.6; flex: 1; min-height: 42px; }
.rule-foot { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding-top: 12px; border-top: 1px solid var(--line); }
.skel-list { display: flex; flex-direction: column; gap: 12px; padding: 6px 0; }
</style>
