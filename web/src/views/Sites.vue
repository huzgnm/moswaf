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
    flood_rps: 0,
    force_https: false,
    acme_enabled: false,
    acme_email: '',
    tls_cert: '',
    tls_key: '',
    auth_enabled: false,
    auth_paths: '',
  }
}

// The gate can only be switched on for a site that will have HTTPS. Over plain
// HTTP it would hand the password and then the session cookie to everybody on the
// path while appearing to work, so the switch is disabled rather than the save
// refused - an explanation next to a control that cannot be used beats an error
// after filling the form in.
function canGate(f) {
  return Boolean(f.acme_enabled || f.tls_cert || (editing.value && editing.value.has_tls))
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
    // "/" on its own is how the server stores "the whole site", and showing it in
    // the box would invite somebody to edit it into something narrower by
    // accident. Empty reads as what it means: everything.
    auth_paths: (site.auth_paths || []).filter((p) => p !== '/').join(', '),
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
    flood_rps: Number(form.value.flood_rps) || 0,
    auth_enabled: canGate(form.value) && form.value.auth_enabled,
    auth_paths: form.value.auth_paths.split(',').map((p) => p.trim()).filter(Boolean),
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

// ---------------------------------------------------------------- accounts
//
// The people allowed through a site's login gate. Kept in its own panel rather
// than inside the site form: creating an account is a different action from
// editing a site, and burying it in a form with a Save button would make it
// ambiguous whether the account exists before that button is pressed.

const accountsFor = ref(null)
const accounts = ref([])
const accountsBusy = ref(false)
const newAccount = ref({ username: '', password: '' })

async function openAccounts(site) {
  accountsFor.value = site
  accounts.value = []
  newAccount.value = { username: '', password: '' }
  await loadAccounts()
}

async function loadAccounts() {
  if (!accountsFor.value) return
  accountsBusy.value = true
  try {
    accounts.value = await api.list(`/api/sites/${accountsFor.value.id}/users`)
  } catch (e) {
    notify(e.message, true)
  } finally {
    accountsBusy.value = false
  }
}

async function addAccount() {
  accountsBusy.value = true
  try {
    await api.post(`/api/sites/${accountsFor.value.id}/users`, {
      username: newAccount.value.username,
      password: newAccount.value.password,
    })
    newAccount.value = { username: '', password: '' }
    notify(t('sites.auth.added'))
    await loadAccounts()
    await load()
  } catch (e) {
    notify(e.message, true)
  } finally {
    accountsBusy.value = false
  }
}

async function resetPassword(u) {
  const pw = prompt(t('sites.auth.newPasswordFor', { name: u.username }))
  if (!pw) return
  try {
    await api.put(`/api/sites/${accountsFor.value.id}/users/${u.id}/password`, { password: pw })
    // Worth saying out loud: a password change is also a sign-out, and somebody
    // who expected only the first would otherwise be surprised by the second.
    notify(t('sites.auth.passwordChanged'))
    await loadAccounts()
  } catch (e) {
    notify(e.message, true)
  }
}

async function revokeAccount(u) {
  if (!confirm(t('sites.auth.revokeConfirm', { name: u.username }))) return
  try {
    await api.post(`/api/sites/${accountsFor.value.id}/users/${u.id}/revoke`)
    notify(t('sites.auth.revoked'))
    await loadAccounts()
  } catch (e) {
    notify(e.message, true)
  }
}

async function deleteAccount(u) {
  if (!confirm(t('sites.auth.deleteConfirm', { name: u.username }))) return
  try {
    await api.del(`/api/sites/${accountsFor.value.id}/users/${u.id}`)
    notify(t('sites.auth.deleted'))
    await loadAccounts()
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

    <div v-else class="table-wrap">
      <table class="table">
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
              <span v-if="s.auth_enabled" class="tag tag-ok" style="margin-left:6px"
                    :title="t('sites.auth.badgeHint')">{{ t('sites.auth.badge') }}</span>
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
              <button
                v-if="s.auth_enabled"
                class="btn btn-sm" style="margin-left:6px"
                :title="t('sites.auth.manageHint')"
                @click="openAccounts(s)"
              >{{ t('sites.auth.manage') }}</button>
              <button class="btn btn-sm" style="margin-left:6px" @click="openEdit(s)">{{ t('common.edit') }}</button>
              <button class="btn btn-sm btn-danger" style="margin-left:6px" @click="remove(s)">{{ t('common.delete') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
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

    <div class="field">
      <label class="label">{{ t('sites.form.floodRPS') }}</label>
      <input v-model="form.flood_rps" type="number" min="0" class="input mono" />
      <div class="hint">{{ t('sites.form.floodRPSHint') }}</div>
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

    <div class="divider"></div>

    <label class="switch" :class="{ 'is-disabled': !canGate(form) }">
      <input v-model="form.auth_enabled" type="checkbox" :disabled="!canGate(form)" />
      <span class="track"></span>
      <span>{{ t('sites.form.authEnabled') }}</span>
    </label>
    <div class="hint" style="margin-top:6px">
      {{ canGate(form) ? t('sites.form.authHint') : t('sites.form.authNeedsHttps') }}
    </div>

    <div v-if="form.auth_enabled && canGate(form)" class="field" style="margin-top:14px">
      <label class="label">{{ t('sites.form.authPaths') }}</label>
      <input v-model="form.auth_paths" class="input mono" placeholder="/admin, /billing" />
      <div class="hint">{{ t('sites.form.authPathsHint') }}</div>
    </div>
    <div v-if="form.auth_enabled && canGate(form) && !editing" class="hint"
         style="margin-top:8px; color:#d8b46a">
      {{ t('sites.form.authNoAccountsYet') }}
    </div>
  </Modal>

  <Modal
    v-if="accountsFor"
    :title="t('sites.auth.title', { name: accountsFor.name })"
    :busy="accountsBusy"
    :hide-submit="true"
    @close="accountsFor = null"
  >
    <div class="hint" style="margin-bottom:14px">{{ t('sites.auth.sub') }}</div>

    <div v-if="!accounts.length" class="empty" style="padding:18px 0">
      {{ accountsBusy ? t('common.loading') : t('sites.auth.empty') }}
    </div>

    <div v-else class="table-wrap" style="margin-bottom:18px">
      <table class="table">
        <thead>
          <tr>
            <th>{{ t('sites.auth.colUser') }}</th>
            <th>{{ t('sites.auth.colCreated') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in accounts" :key="u.id">
            <td class="mono">{{ u.username }}</td>
            <td class="card-sub">{{ new Date(u.created_at).toLocaleDateString() }}</td>
            <td style="text-align:right; white-space:nowrap">
              <button class="btn btn-sm" @click="resetPassword(u)">{{ t('sites.auth.reset') }}</button>
              <button class="btn btn-sm" style="margin-left:6px" @click="revokeAccount(u)">
                {{ t('sites.auth.revoke') }}
              </button>
              <button class="btn btn-sm btn-danger" style="margin-left:6px" @click="deleteAccount(u)">
                {{ t('common.delete') }}
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">{{ t('sites.auth.colUser') }}</label>
        <input v-model="newAccount.username" class="input mono" autocomplete="off" />
      </div>
      <div class="field grow">
        <label class="label">{{ t('sites.auth.password') }}</label>
        <input v-model="newAccount.password" type="password" class="input" autocomplete="new-password" />
      </div>
    </div>
    <div class="hint" style="margin:-8px 0 14px">{{ t('sites.auth.passwordHint') }}</div>
    <button
      class="btn btn-primary"
      :disabled="accountsBusy || !newAccount.username || !newAccount.password"
      @click="addAccount"
    >{{ t('sites.auth.add') }}</button>
  </Modal>
</template>
