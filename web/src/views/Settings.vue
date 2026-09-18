<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api, notify } from '../api'
import { t } from '../i18n'
import Icon from '../components/Icon.vue'
import CountryPicker from '../components/CountryPicker.vue'

const settings = ref(null)

// The country list the geo rule can be built from. Fetched separately: the
// dataset arrives a minute after boot, and until it does no rule can apply.
const geo = ref(null)        // { ready, countries, dataset }
const geoError = ref('')

async function loadGeo() {
  geoError.value = ''
  try {
    geo.value = await api.get('/api/geo/countries')
  } catch (e) {
    geo.value = null
    geoError.value = e.message
  }
}
const loadError = ref('')
const busy = ref(false)
const pwd = ref({ current: '', next: '', confirm: '' })
const pwdBusy = ref(false)
const proxies = ref('')

async function load() {
  loadError.value = ''
  try {
    const st = await api.get('/api/settings')
    st.geo_mode = st.geo_mode || 'off'
    st.geo_countries = st.geo_countries || []
    settings.value = st
    proxies.value = (st.trusted_proxies || []).join(', ')
  } catch (e) {
    loadError.value = e.message
  }
}

// Everything is sent back, including the rate-limit fields that now have their
// own page: the server merges what it receives over what it has, so leaving a
// field out would be fine too, but sending the whole object keeps this one
// Save button honest about what it saves.
async function save() {
  busy.value = true
  try {
    const payload = {
      ...settings.value,
      trusted_proxies: proxies.value.split(',').map((s) => s.trim()).filter(Boolean),
      global_rate_rps: Number(settings.value.global_rate_rps),
      global_rate_burst: Number(settings.value.global_rate_burst),
      ban_seconds: Number(settings.value.ban_seconds),
      challenge_difficulty: Number(settings.value.challenge_difficulty),
      challenge_ttl: Number(settings.value.challenge_ttl),
      block_status: Number(settings.value.block_status),
      flood_rps: Number(settings.value.flood_rps),
      flood_error_rate: Number(settings.value.flood_error_rate),
      flood_hold: Number(settings.value.flood_hold),
      max_body_scan: Number(settings.value.max_body_scan),
      log_retain_days: Number(settings.value.log_retain_days),
      geo_mode: settings.value.geo_mode || 'off',
      geo_countries: (settings.value.geo_countries || []).map((c) => c.toUpperCase()),
    }
    settings.value = await api.put('/api/settings', payload)
    proxies.value = (settings.value.trusted_proxies || []).join(', ')
    notify(t('settings.saved'))
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

async function changePassword() {
  if (pwd.value.next !== pwd.value.confirm) {
    notify(t('settings.passwordMismatch'), true)
    return
  }
  pwdBusy.value = true
  try {
    await api.post('/api/auth/password', { current: pwd.value.current, new: pwd.value.next })
    pwd.value = { current: '', next: '', confirm: '' }
    notify(t('settings.passwordChanged'))
  } catch (e) {
    notify(e.message, true)
  } finally {
    pwdBusy.value = false
  }
}

async function republish() {
  try {
    const res = await api.post('/api/system/publish')
    notify(t('settings.resynced', { version: res.version }))
  } catch (e) {
    notify(e.message, true)
  }
}

// While the dataset is still downloading, keep asking so the warning clears on
// its own instead of leaving the operator to reload the page.
let geoTimer = null
onMounted(() => {
  load()
  loadGeo()
  geoTimer = setInterval(() => { if (!geo.value?.ready) loadGeo() }, 20000)
})
onUnmounted(() => clearInterval(geoTimer))
</script>

<template>
  <div class="page-head">
    <div>
      <h2>{{ t('settings.policy') }}</h2>
      <p class="page-sub">{{ t('settings.policySub') }}</p>
    </div>
    <div class="page-actions">
      <button type="button" class="btn btn-primary" :disabled="busy || !settings" @click="save">
        <Icon name="check" />{{ busy ? t('common.saving') : t('settings.saveButton') }}
      </button>
    </div>
  </div>

  <div v-if="loadError" class="empty card">
    <Icon name="alert" />
    <b>{{ t('settings.loadFailed') }}</b>
    <span class="empty-hint">{{ loadError }}</span>
    <button type="button" class="btn btn-sm" @click="load"><Icon name="refresh" />{{ t('common.retry') }}</button>
  </div>

  <template v-else-if="settings">
    <div class="grid grid-2 settings-grid">
      <div class="card">
        <div class="card-head">
          <div>
            <div class="card-title">{{ t('settings.section.blocking') }}</div>
            <div class="card-sub">{{ t('settings.section.blockingSub') }}</div>
          </div>
        </div>

        <div class="field">
          <label class="label">{{ t('settings.defaultMode') }}</label>
          <select v-model="settings.default_mode" class="select">
            <option value="protect">{{ t('sites.form.modeProtect') }}</option>
            <option value="monitor">{{ t('sites.form.modeMonitor') }}</option>
            <option value="off">{{ t('sites.mode.off') }}</option>
          </select>
        </div>
        <div class="field">
          <label class="label">{{ t('settings.blockStatus') }}</label>
          <input v-model="settings.block_status" type="number" class="input mono" />
          <div class="hint">{{ t('settings.blockStatusHint') }}</div>
        </div>
        <div class="field">
          <label class="label">{{ t('settings.maxBodyScan') }}</label>
          <input v-model="settings.max_body_scan" type="number" class="input mono" />
        </div>
        <label class="switch">
          <input v-model="settings.scan_body" type="checkbox" />
          <span class="track"></span>
          <span>{{ t('settings.scanBody') }}</span>
        </label>
      </div>

      <div class="card">
        <div class="card-head">
          <div>
            <div class="card-title">{{ t('settings.section.challenge') }}</div>
            <div class="card-sub">{{ t('settings.section.challengeSub') }}</div>
          </div>
        </div>
        <div class="field">
          <label class="label">{{ t('settings.difficulty') }}</label>
          <input v-model="settings.challenge_difficulty" type="number" class="input mono" min="8" max="24" />
          <div class="hint">{{ t('settings.difficultyHint') }}</div>
        </div>
        <div class="field">
          <label class="label">{{ t('settings.challengeTTL') }}</label>
          <input v-model="settings.challenge_ttl" type="number" class="input mono" />
        </div>
        <div class="alert alert-info" style="margin-top:4px">
          <Icon name="info" />
          <div class="alert-body">{{ t('settings.rateMoved') }} <router-link to="/ratelimit">{{ t('nav.ratelimit') }}</router-link></div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div>
            <div class="card-title">{{ t('settings.section.network') }}</div>
            <div class="card-sub">{{ t('settings.section.networkSub') }}</div>
          </div>
        </div>
        <div class="field">
          <label class="label">{{ t('settings.realIPHeader') }}</label>
          <select v-model="settings.real_ip_header" class="select">
            <option value="">{{ t('settings.realIPNone') }}</option>
            <option value="X-Forwarded-For">X-Forwarded-For</option>
            <option value="CF-Connecting-IP">CF-Connecting-IP (Cloudflare)</option>
            <option value="X-Real-IP">X-Real-IP</option>
          </select>
          <div class="hint warn">{{ t('settings.realIPHint') }}</div>
        </div>
        <div class="field">
          <label class="label">{{ t('settings.trustedProxies') }}</label>
          <input v-model="proxies" class="input mono" placeholder="173.245.48.0/20, 103.21.244.0/22" />
          <div class="hint">{{ t('settings.trustedProxiesHint') }}</div>
        </div>
      </div>

      <div class="card">
        <div class="card-head">
          <div>
            <div class="card-title">{{ t('settings.section.logging') }}</div>
            <div class="card-sub">{{ t('settings.section.loggingSub') }}</div>
          </div>
        </div>
        <div class="field">
          <label class="label">{{ t('settings.retainDays') }}</label>
          <input v-model="settings.log_retain_days" type="number" class="input mono" />
        </div>
        <label class="switch">
          <input v-model="settings.log_allowed" type="checkbox" />
          <span class="track"></span>
          <span>{{ t('settings.logAllowed') }}</span>
        </label>
      </div>
    </div>

    <!-- country rule -->
    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">{{ t('geo.title') }}</div>
          <div class="card-sub">{{ t('geo.sub') }}</div>
        </div>
        <span v-if="geo?.ready" class="tag tag-ok"><span class="dot"></span>{{ t('geo.datasetReady', { n: geo.dataset?.ranges ? new Intl.NumberFormat().format(geo.dataset.ranges) : '?', month: geo.dataset?.month || '' }) }}</span>
      </div>

      <div v-if="geoError" class="alert alert-warn" style="margin-bottom:14px">
        <Icon name="alert" />
        <div class="alert-body">{{ t('geo.loadFailed', { error: geoError }) }} <button type="button" class="btn-link" @click="loadGeo">{{ t('common.retry') }}</button></div>
      </div>
      <div v-else-if="geo && !geo.ready" class="alert alert-warn" style="margin-bottom:14px">
        <Icon name="clock" />
        <div class="alert-body"><b>{{ t('geo.notReady') }}</b> {{ t('geo.notReadyHint') }}<span v-if="geo.dataset?.last_error"> {{ t('geo.lastError', { error: geo.dataset.last_error }) }}</span></div>
      </div>

      <div class="grid grid-2 geo-grid">
        <div>
          <div class="field">
            <label class="label">{{ t('geo.mode') }}</label>
            <select v-model="settings.geo_mode" class="select">
              <option value="off">{{ t('geo.modeOff') }}</option>
              <option value="block">{{ t('geo.modeBlock') }}</option>
              <option value="allow">{{ t('geo.modeAllow') }}</option>
            </select>
          </div>

          <div v-if="settings.geo_mode === 'allow' && !(settings.geo_countries || []).length" class="alert alert-critical" style="margin-bottom:12px">
            <Icon name="alert" />
            <div class="alert-body"><b>{{ t('geo.allowEmpty') }}</b> {{ t('geo.allowEmptyHint') }}</div>
          </div>
          <div v-else-if="settings.geo_mode === 'allow'" class="alert alert-warn" style="margin-bottom:12px">
            <Icon name="info" />
            <div class="alert-body">{{ t('geo.allowCrawlers') }}</div>
          </div>

          <ul v-if="settings.geo_mode !== 'off'" class="geo-notes">
            <li>{{ t('geo.noteUnknown') }}</li>
            <li>{{ t('geo.noteCrawlers') }}</li>
            <li>{{ t('geo.noteAction') }}</li>
          </ul>
          <div v-else class="hint">{{ t('geo.offHint') }}</div>
        </div>

        <div>
          <label class="label">{{ settings.geo_mode === 'allow' ? t('geo.listAllow') : t('geo.listBlock') }}</label>
          <CountryPicker
            v-model="settings.geo_countries"
            :countries="geo?.countries || []"
            :disabled="settings.geo_mode === 'off' || !geo?.ready"
          />
        </div>
      </div>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <div class="card-head">
          <div>
            <div class="card-title">{{ t('settings.password') }}</div>
            <div class="card-sub">{{ t('settings.passwordSub') }}</div>
          </div>
        </div>
        <form @submit.prevent="changePassword">
          <div class="field">
            <label class="label">{{ t('settings.currentPassword') }}</label>
            <input v-model="pwd.current" type="password" class="input" autocomplete="current-password" />
          </div>
          <div class="row">
            <div class="field grow">
              <label class="label">{{ t('settings.newPassword') }}</label>
              <input v-model="pwd.next" type="password" class="input" autocomplete="new-password" />
            </div>
            <div class="field grow">
              <label class="label">{{ t('settings.repeatPassword') }}</label>
              <input v-model="pwd.confirm" type="password" class="input" autocomplete="new-password" />
            </div>
          </div>
          <button type="submit" class="btn" :disabled="pwdBusy || !pwd.current || !pwd.next"><Icon name="key" />{{ t('settings.changePassword') }}</button>
        </form>
      </div>

      <div class="card">
        <div class="card-head">
          <div>
            <div class="card-title">{{ t('settings.maintenance') }}</div>
            <div class="card-sub">{{ t('settings.maintenanceSub') }}</div>
          </div>
        </div>
        <button type="button" class="btn" @click="republish"><Icon name="refresh" />{{ t('settings.resync') }}</button>
      </div>
    </div>
  </template>

  <div v-else class="card">
    <div class="skel-rows"><div v-for="i in 6" :key="i" class="skel skel-line"></div></div>
  </div>
</template>

<style scoped>
.settings-grid { align-items: start; }
.geo-grid { align-items: start; }
.geo-notes { margin: 0; padding-left: 18px; color: var(--ink-2); font-size: 12.5px; line-height: 1.6; }
.geo-notes li + li { margin-top: 4px; }
.skel-rows { display: flex; flex-direction: column; gap: 14px; padding: 8px 0; }
</style>
