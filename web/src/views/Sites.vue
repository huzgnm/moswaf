<script setup>
import { ref, onMounted } from 'vue'
import { api, notify } from '../api'
import { t } from '../i18n'
import Modal from '../components/Modal.vue'

const sites = ref([])
const loading = ref(true)
const showForm = ref(false)
const busy = ref(false)
const editing = ref(null)
const form = ref(blank())

function blank() {
  return {
    name: '',
    domains: '',
    upstream_scheme: 'http',
    upstream_host: '',
    upstream_port: 80,
    mode: 'protect',
    challenge: 'auto',
    rate_rps: 0,
    rate_burst: 0,
    force_https: false,
    acme_enabled: false,
    acme_email: '',
    tls_cert: '',
    tls_key: '',
  }
}

// Certificate column: what an operator needs at a glance is whether TLS works and
// how long it keeps working.
function certLabel(s) {
  if (!s.has_tls) return t(s.acme_enabled ? 'sites.cert.pending' : 'sites.cert.none')
  if (!s.cert_expires_at) return t(s.force_https ? 'sites.cert.forced' : 'sites.cert.present')
  const days = Math.floor((new Date(s.cert_expires_at) - Date.now()) / 86400000)
  if (days < 0) return t('sites.cert.expired')
  return t('sites.cert.daysLeft', { days })
}

function certTone(s) {
  if (!s.has_tls) return s.acme_enabled ? 'tag-monitor' : 'tag-off'
  if (!s.cert_expires_at) return 'tag-ok'
  const days = Math.floor((new Date(s.cert_expires_at) - Date.now()) / 86400000)
  return days < 0 ? 'tag-deny' : days < 15 ? 'tag-monitor' : 'tag-ok'
}

const issuing = ref('')

async function issueCert(site) {
  issuing.value = site.id
  try {
    await api.post(`/api/sites/${site.id}/certificate`)
    notify(t('sites.certIssued', { name: site.name }))
    await load()
  } catch (e) {
    notify(e.message, true)
  } finally {
    issuing.value = ''
  }
}

function modeLabel(mode) {
  return t(`sites.mode.${mode}`)
}

async function load() {
  loading.value = true
  try {
    sites.value = await api.list('/api/sites')
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = null
  form.value = blank()
  showForm.value = true
}

function openEdit(site) {
  editing.value = site
  form.value = {
    ...site,
    domains: site.domains.join(', '),
    tls_cert: '',
    tls_key: '',
  }
  showForm.value = true
}

async function save() {
  const payload = {
    ...form.value,
    domains: form.value.domains.split(',').map((d) => d.trim()).filter(Boolean),
    upstream_port: Number(form.value.upstream_port) || 80,
    rate_rps: Number(form.value.rate_rps) || 0,
    rate_burst: Number(form.value.rate_burst) || 0,
  }
  busy.value = true
  try {
    if (editing.value) {
      await api.put(`/api/sites/${editing.value.id}`, payload)
      notify(t('sites.updated'))
    } else {
      await api.post('/api/sites', payload)
      notify(t('sites.created'))
    }
    showForm.value = false
    await load()
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

async function remove(site) {
  if (!confirm(t('sites.deleteConfirm', { name: site.name }))) return
  try {
    await api.del(`/api/sites/${site.id}`)
    notify(t('sites.deleted'))
    await load()
  } catch (e) {
    notify(e.message, true)
  }
}

onMounted(load)
</script>

<template>
  <div class="card">
    <div class="card-head">
      <div>
        <div class="card-title">{{ t('sites.title') }}</div>
        <div class="card-sub">{{ t('sites.sub') }}</div>
      </div>
      <button class="btn btn-primary" @click="openCreate">{{ t('sites.addButton') }}</button>
    </div>

    <div v-if="loading" class="empty">{{ t('common.loading') }}</div>
    <div v-else-if="!sites.length" class="empty">{{ t('sites.empty') }}</div>

    <table v-else class="table">
      <thead>
        <tr>
          <th>{{ t('sites.col.name') }}</th>
          <th>{{ t('sites.col.domains') }}</th>
          <th>{{ t('sites.col.upstream') }}</th>
          <th>{{ t('sites.col.mode') }}</th>
          <th>{{ t('sites.col.rate') }}</th>
          <th>{{ t('sites.col.https') }}</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="s in sites" :key="s.id">
          <td>{{ s.name }}</td>
          <td class="mono truncate">{{ s.domains.join(', ') }}</td>
          <td class="mono">{{ s.upstream_scheme }}://{{ s.upstream_host }}:{{ s.upstream_port }}</td>
          <td>
            <span class="tag" :class="s.mode === 'protect' ? 'tag-ok' : s.mode === 'monitor' ? 'tag-monitor' : 'tag-off'">
              <span class="dot"></span>{{ modeLabel(s.mode) }}
            </span>
          </td>
          <td class="mono">
            {{ s.rate_rps ? t('sites.rate.rps', { n: s.rate_rps }) : t('sites.rate.default') }}
          </td>
          <td>
            <span class="tag" :class="certTone(s)" :title="s.acme_last_error || ''">
              <span class="dot"></span>{{ certLabel(s) }}
            </span>
            <span v-if="s.acme_enabled" class="card-sub" style="margin-left:6px">{{ t('sites.cert.auto') }}</span>
          </td>
          <td style="text-align:right; white-space:nowrap">
            <button
              v-if="s.acme_enabled"
              class="btn btn-sm" :disabled="issuing === s.id"
              :title="t('sites.getCertHint')"
              @click="issueCert(s)"
            >{{ issuing === s.id ? t('sites.getCertBusy') : t('sites.getCert') }}</button>
            <button class="btn btn-sm" style="margin-left:6px" @click="openEdit(s)">{{ t('common.edit') }}</button>
            <button class="btn btn-sm btn-danger" style="margin-left:6px" @click="remove(s)">{{ t('common.delete') }}</button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <Modal
    v-if="showForm"
    :title="editing ? t('sites.form.editTitle', { name: editing.name }) : t('sites.form.addTitle')"
    :busy="busy"
    @close="showForm = false"
    @submit="save"
  >
    <div class="field">
      <label class="label">{{ t('sites.form.name') }}</label>
      <input v-model="form.name" class="input" :placeholder="t('sites.form.namePlaceholder')" />
    </div>

    <div class="field">
      <label class="label">{{ t('sites.form.domains') }}</label>
      <input v-model="form.domains" class="input mono" placeholder="example.com, www.example.com" />
      <div class="hint">{{ t('sites.form.domainsHint') }}</div>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">{{ t('sites.form.scheme') }}</label>
        <select v-model="form.upstream_scheme" class="select">
          <option value="http">http</option>
          <option value="https">https</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">{{ t('sites.form.host') }}</label>
        <input v-model="form.upstream_host" class="input mono" :placeholder="t('sites.form.hostPlaceholder')" />
      </div>
      <div class="field" style="width:110px">
        <label class="label">{{ t('sites.form.port') }}</label>
        <input v-model="form.upstream_port" type="number" class="input mono" />
      </div>
    </div>
    <div class="hint" style="margin:-8px 0 14px">
      {{ t('sites.form.hostHint', { code: 'host.docker.internal' }) }}
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">{{ t('sites.form.mode') }}</label>
        <select v-model="form.mode" class="select">
          <option value="protect">{{ t('sites.form.modeProtect') }}</option>
          <option value="monitor">{{ t('sites.form.modeMonitor') }}</option>
          <option value="off">{{ t('sites.form.modeOff') }}</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">{{ t('sites.form.challenge') }}</label>
        <select v-model="form.challenge" class="select">
          <option value="auto">{{ t('sites.form.challengeAuto') }}</option>
          <option value="always">{{ t('sites.form.challengeAlways') }}</option>
          <option value="off">{{ t('sites.form.challengeOff') }}</option>
        </select>
      </div>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">{{ t('sites.form.rps') }}</label>
        <input v-model="form.rate_rps" type="number" class="input mono" />
        <div class="hint">{{ t('sites.form.rpsHint') }}</div>
      </div>
      <div class="field grow">
        <label class="label">{{ t('sites.form.burst') }}</label>
        <input v-model="form.rate_burst" type="number" class="input mono" />
      </div>
    </div>

    <label class="switch" style="margin-bottom:14px">
      <input v-model="form.acme_enabled" type="checkbox" />
      <span class="track"></span>
      <span>{{ t('sites.form.acme') }}</span>
    </label>

    <div v-if="form.acme_enabled" class="field">
      <label class="label">{{ t('sites.form.acmeEmail') }}</label>
      <input v-model="form.acme_email" class="input" placeholder="ops@example.com" />
      <div class="hint">{{ t('sites.form.acmeHint') }}</div>
    </div>

    <div v-if="editing && editing.acme_last_error" class="hint" style="color:#f0a0a0; margin-bottom:14px">
      {{ t('sites.form.acmeLastError', { error: editing.acme_last_error }) }}
    </div>

    <div v-show="!form.acme_enabled" class="field">
      <label class="label">{{ t('sites.form.tlsCert') }}</label>
      <textarea
        v-model="form.tls_cert" class="input"
        :placeholder="editing && editing.has_tls ? t('sites.form.keepCert') : '-----BEGIN CERTIFICATE-----'"
      ></textarea>
    </div>
    <div v-show="!form.acme_enabled" class="field">
      <label class="label">{{ t('sites.form.tlsKey') }}</label>
      <textarea
        v-model="form.tls_key" class="input"
        :placeholder="editing && editing.has_tls ? t('sites.form.keepKey') : '-----BEGIN PRIVATE KEY-----'"
      ></textarea>
    </div>

    <label class="switch">
      <input v-model="form.force_https" type="checkbox" />
      <span class="track"></span>
      <span>{{ t('sites.form.forceHttps') }}</span>
    </label>
  </Modal>
</template>
