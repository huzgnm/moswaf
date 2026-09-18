<script setup>
import { ref, onMounted } from 'vue'
import { api, notify } from '../api'
import { t } from '../i18n'

const settings = ref(null)
const busy = ref(false)
const pwd = ref({ current: '', next: '', confirm: '' })
const pwdBusy = ref(false)
const proxies = ref('')

async function load() {
  try {
    settings.value = await api.get('/api/settings')
    proxies.value = (settings.value.trusted_proxies || []).join(', ')
  } catch (e) {
    notify(e.message, true)
  }
}

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
      max_body_scan: Number(settings.value.max_body_scan),
      log_retain_days: Number(settings.value.log_retain_days),
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

onMounted(load)
</script>

<template>
  <div v-if="settings">
    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">{{ t('settings.policy') }}</div>
          <div class="card-sub">{{ t('settings.policySub') }}</div>
        </div>
        <button class="btn btn-primary" :disabled="busy" @click="save">
          {{ busy ? t('common.saving') : t('settings.saveButton') }}
        </button>
      </div>

      <div class="grid grid-2">
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
          <label class="label">{{ t('settings.rps') }}</label>
          <input v-model="settings.global_rate_rps" type="number" class="input mono" />
        </div>
        <div class="field">
          <label class="label">{{ t('settings.burst') }}</label>
          <input v-model="settings.global_rate_burst" type="number" class="input mono" />
          <div class="hint">{{ t('settings.burstHint') }}</div>
        </div>

        <div class="field">
          <label class="label">{{ t('settings.banSeconds') }}</label>
          <input v-model="settings.ban_seconds" type="number" class="input mono" />
          <div class="hint">{{ t('settings.banSecondsHint') }}</div>
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
        <div class="field">
          <label class="label">{{ t('settings.maxBodyScan') }}</label>
          <input v-model="settings.max_body_scan" type="number" class="input mono" />
        </div>

        <div class="field">
          <label class="label">{{ t('settings.realIPHeader') }}</label>
          <select v-model="settings.real_ip_header" class="select">
            <option value="">{{ t('settings.realIPNone') }}</option>
            <option value="X-Forwarded-For">X-Forwarded-For</option>
            <option value="CF-Connecting-IP">CF-Connecting-IP (Cloudflare)</option>
            <option value="X-Real-IP">X-Real-IP</option>
          </select>
          <div class="hint">{{ t('settings.realIPHint') }}</div>
        </div>
        <div class="field">
          <label class="label">{{ t('settings.trustedProxies') }}</label>
          <input v-model="proxies" class="input mono" placeholder="173.245.48.0/20, 103.21.244.0/22" />
          <div class="hint">{{ t('settings.trustedProxiesHint') }}</div>
        </div>

        <div class="field">
          <label class="label">{{ t('settings.retainDays') }}</label>
          <input v-model="settings.log_retain_days" type="number" class="input mono" />
        </div>
        <div class="field" style="display:flex; flex-direction:column; gap:12px; justify-content:center">
          <label class="switch">
            <input v-model="settings.scan_body" type="checkbox" />
            <span class="track"></span>
            <span>{{ t('settings.scanBody') }}</span>
          </label>
          <label class="switch">
            <input v-model="settings.log_allowed" type="checkbox" />
            <span class="track"></span>
            <span>{{ t('settings.logAllowed') }}</span>
          </label>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-title">{{ t('settings.password') }}</div>
      </div>
      <div class="grid grid-2">
        <div class="field">
          <label class="label">{{ t('settings.currentPassword') }}</label>
          <input v-model="pwd.current" type="password" class="input" autocomplete="current-password" />
        </div>
        <div></div>
        <div class="field">
          <label class="label">{{ t('settings.newPassword') }}</label>
          <input v-model="pwd.next" type="password" class="input" autocomplete="new-password" />
        </div>
        <div class="field">
          <label class="label">{{ t('settings.repeatPassword') }}</label>
          <input v-model="pwd.confirm" type="password" class="input" autocomplete="new-password" />
        </div>
      </div>
      <button class="btn" :disabled="pwdBusy" @click="changePassword">{{ t('settings.changePassword') }}</button>
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">{{ t('settings.maintenance') }}</div>
          <div class="card-sub">{{ t('settings.maintenanceSub') }}</div>
        </div>
        <button class="btn" @click="republish">{{ t('settings.resync') }}</button>
      </div>
    </div>
  </div>

  <div v-else class="empty">{{ t('settings.loading') }}</div>
</template>
