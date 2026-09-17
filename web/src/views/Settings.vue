<script setup>
import { ref, onMounted } from 'vue'
import { api, notify } from '../api'

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
    notify('Saved and pushed down to the data plane')
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

async function changePassword() {
  if (pwd.value.next !== pwd.value.confirm) {
    notify('The two new password fields do not match', true)
    return
  }
  pwdBusy.value = true
  try {
    await api.post('/api/auth/password', { current: pwd.value.current, new: pwd.value.next })
    pwd.value = { current: '', next: '', confirm: '' }
    notify('Password changed')
  } catch (e) {
    notify(e.message, true)
  } finally {
    pwdBusy.value = false
  }
}

async function republish() {
  try {
    const res = await api.post('/api/system/publish')
    notify(`Full configuration pushed again (version ${res.version})`)
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
          <div class="card-title">Global policy</div>
          <div class="card-sub">Applies to every site that does not set its own values</div>
        </div>
        <button class="btn btn-primary" :disabled="busy" @click="save">
          {{ busy ? 'Saving...' : 'Save changes' }}
        </button>
      </div>

      <div class="grid grid-2">
        <div class="field">
          <label class="label">Default mode</label>
          <select v-model="settings.default_mode" class="select">
            <option value="protect">Protect - actually block</option>
            <option value="monitor">Monitor only - log, never block</option>
            <option value="off">Off</option>
          </select>
        </div>
        <div class="field">
          <label class="label">Status code when blocking</label>
          <input v-model="settings.block_status" type="number" class="input mono" />
          <div class="hint">403 is the default. Use 444 to drop the connection without any reply.</div>
        </div>

        <div class="field">
          <label class="label">Requests per second per IP</label>
          <input v-model="settings.global_rate_rps" type="number" class="input mono" />
        </div>
        <div class="field">
          <label class="label">Limit over a 10 second window</label>
          <input v-model="settings.global_rate_burst" type="number" class="input mono" />
          <div class="hint">Catches attackers who pace themselves to stay under the per-second threshold.</div>
        </div>

        <div class="field">
          <label class="label">Temporary ban duration (seconds)</label>
          <input v-model="settings.ban_seconds" type="number" class="input mono" />
          <div class="hint">Applied after three threshold breaches within one minute.</div>
        </div>
        <div class="field">
          <label class="label">JS challenge difficulty (bits)</label>
          <input v-model="settings.challenge_difficulty" type="number" class="input mono" min="8" max="24" />
          <div class="hint">
            16 bits is roughly 0.1-0.3s on the visitor's machine, and every extra bit doubles
            the work. Only raise it to 18-20 while you are under a heavy flood.
          </div>
        </div>

        <div class="field">
          <label class="label">Challenge cookie lifetime (seconds)</label>
          <input v-model="settings.challenge_ttl" type="number" class="input mono" />
        </div>
        <div class="field">
          <label class="label">Maximum body size scanned (bytes)</label>
          <input v-model="settings.max_body_scan" type="number" class="input mono" />
        </div>

        <div class="field">
          <label class="label">Header carrying the real client IP</label>
          <select v-model="settings.real_ip_header" class="select">
            <option value="">None - use the direct connection IP</option>
            <option value="X-Forwarded-For">X-Forwarded-For</option>
            <option value="CF-Connecting-IP">CF-Connecting-IP (Cloudflare)</option>
            <option value="X-Real-IP">X-Real-IP</option>
          </select>
          <div class="hint">
            Only enable this when a CDN or proxy really sits in front of MosWAF - otherwise
            an attacker can simply forge the header and spoof any IP.
          </div>
        </div>
        <div class="field">
          <label class="label">Trusted proxies (comma separated)</label>
          <input v-model="proxies" class="input mono" placeholder="173.245.48.0/20, 103.21.244.0/22" />
          <div class="hint">Empty means every source is trusted - only safe when MosWAF is not exposed to the internet.</div>
        </div>

        <div class="field">
          <label class="label">Keep the attack log for (days)</label>
          <input v-model="settings.log_retain_days" type="number" class="input mono" />
        </div>
        <div class="field" style="display:flex; flex-direction:column; gap:12px; justify-content:center">
          <label class="switch">
            <input v-model="settings.scan_body" type="checkbox" />
            <span class="track"></span>
            <span>Scan POST bodies</span>
          </label>
          <label class="switch">
            <input v-model="settings.log_allowed" type="checkbox" />
            <span class="track"></span>
            <span>Log normal requests too (uses a lot of disk)</span>
          </label>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-title">Change admin password</div>
      </div>
      <div class="grid grid-2">
        <div class="field">
          <label class="label">Current password</label>
          <input v-model="pwd.current" type="password" class="input" autocomplete="current-password" />
        </div>
        <div></div>
        <div class="field">
          <label class="label">New password</label>
          <input v-model="pwd.next" type="password" class="input" autocomplete="new-password" />
        </div>
        <div class="field">
          <label class="label">Repeat new password</label>
          <input v-model="pwd.confirm" type="password" class="input" autocomplete="new-password" />
        </div>
      </div>
      <button class="btn" :disabled="pwdBusy" @click="changePassword">Change password</button>
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">Maintenance</div>
          <div class="card-sub">Push the whole configuration to OpenResty again if you suspect the data plane has drifted</div>
        </div>
        <button class="btn" @click="republish">Resync data plane</button>
      </div>
    </div>
  </div>

  <div v-else class="empty">Loading settings...</div>
</template>
