<script setup>
import { ref, computed, onMounted } from 'vue'
import { api, notify } from '../api'
import { t } from '../i18n'
import Modal from '../components/Modal.vue'
import Icon from '../components/Icon.vue'
import CountryPicker from '../components/CountryPicker.vue'

const sites = ref([])
const loading = ref(true)

// What the country picker can offer, and what the global rule currently says.
// The second one is why "follow the global rule" is a meaningful choice rather
// than a word: it is shown next to the option, so nobody has to open Settings in
// another tab to find out what they are agreeing to.
const geo = ref(null)         // { ready, countries, dataset }
const globalGeo = ref(null)   // { geo_mode, geo_countries }
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
    // "" is not "off": it means this site follows the global rule, and the two
    // have to stay apart. Collapsing them takes an exemption away from whoever
    // set it, the next time the global rule is edited, without ever saying so.
    geo_mode: '',
    geo_countries: [],
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
function modeTone(mode) {
  return mode === 'protect' ? 'tag-ok' : mode === 'monitor' ? 'tag-monitor' : 'tag-off'
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

async function loadGeo() {
  // Both are optional decoration around the site form: a failure here must not
  // stop somebody editing an upstream, so it is not reported as an error.
  try { geo.value = await api.get('/api/geo/countries') } catch (e) { geo.value = null }
  try {
    const st = await api.get('/api/settings')
    globalGeo.value = { geo_mode: st.geo_mode || 'off', geo_countries: st.geo_countries || [] }
  } catch (e) {
    globalGeo.value = null
  }
}

// One line describing a country rule, used for the global rule under the
// "follow it" option and for the badge in the table.
function geoSummary(mode, countries) {
  const n = (countries || []).length
  if (mode === 'block') return t('geo.summaryBlock', { n })
  if (mode === 'allow') return t('geo.summaryAllow', { n })
  return t('geo.summaryOff')
}

const globalGeoSummary = computed(() =>
  globalGeo.value ? geoSummary(globalGeo.value.geo_mode, globalGeo.value.geo_countries) : ''
)

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
    geo_mode: site.geo_mode || '',
    geo_countries: [...(site.geo_countries || [])],
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
    geo_mode: form.value.geo_mode || '',
    geo_countries: (form.value.geo_countries || []).map((c) => c.toUpperCase()),
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

onMounted(() => { load(); loadGeo() })
</script>

<template>
  <div class="page-head">
    <div>
      <h2>{{ t('sites.title') }}</h2>
      <p class="page-sub">{{ t('sites.sub') }}</p>
    </div>
    <div class="page-actions">
      <button type="button" class="btn btn-primary" @click="openCreate"><Icon name="plus" />{{ t('sites.addButton') }}</button>
    </div>
  </div>

  <div class="card">
    <div v-if="loading" class="skel-rows"><div v-for="i in 4" :key="i" class="skel skel-line"></div></div>
    <div v-else-if="!sites.length" class="empty">
      <Icon name="sites" />
      <b>{{ t('sites.emptyTitle') }}</b>
      <span class="empty-hint">{{ t('sites.empty') }}</span>
      <button type="button" class="btn btn-primary btn-sm" @click="openCreate"><Icon name="plus" />{{ t('sites.addButton') }}</button>
    </div>

    <div v-else class="table-wrap">
      <table class="table">
        <thead>
          <tr>
            <th style="min-width:150px">{{ t('sites.col.name') }}</th>
            <th>{{ t('sites.col.domains') }}</th>
            <th style="min-width:190px">{{ t('sites.col.upstream') }}</th>
            <th>{{ t('sites.col.mode') }}</th>
            <th>{{ t('sites.col.rate') }}</th>
            <th>{{ t('sites.col.https') }}</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in sites" :key="s.id">
            <td><b class="site-name">{{ s.name }}</b></td>
            <td class="mono truncate">{{ s.domains.join(', ') }}</td>
            <td class="mono dim nowrap">{{ s.upstream_scheme }}://{{ s.upstream_host }}:{{ s.upstream_port }}</td>
            <td class="nowrap">
              <span class="tag" :class="modeTone(s.mode)">
                <span class="dot"></span>{{ modeLabel(s.mode) }}
              </span>
              <span v-if="s.auth_enabled" class="tag tag-verify" style="margin-left:6px" :title="t('sites.auth.badgeHint')">
                <Icon name="lock" style="width:11px;height:11px" />{{ t('sites.auth.badge') }}
              </span>
              <span
                v-if="s.geo_mode === 'block' || s.geo_mode === 'allow'"
                class="tag" :class="s.geo_mode === 'allow' ? 'tag-monitor' : 'tag-deny'"
                style="margin-left:6px" :title="geoSummary(s.geo_mode, s.geo_countries)"
              >
                <Icon name="globe" style="width:11px;height:11px" />{{ (s.geo_countries || []).length }}
              </span>
              <span
                v-else-if="s.geo_mode === 'off'"
                class="tag tag-off" style="margin-left:6px" :title="t('geo.tagOffHint')"
              >
                <Icon name="globeOff" style="width:11px;height:11px" />{{ t('geo.tagOff') }}
              </span>
            </td>
            <td class="mono sub">
              {{ s.rate_rps ? t('sites.rate.rps', { n: s.rate_rps }) : t('sites.rate.default') }}
            </td>
            <td class="nowrap">
              <span class="tag" :class="certTone(s)" :title="s.acme_last_error || ''">
                <span class="dot"></span>{{ certLabel(s) }}
              </span>
              <span v-if="s.acme_enabled" class="dim" style="margin-left:6px; font-size:11.5px">{{ t('sites.cert.auto') }}</span>
            </td>
            <td class="actions">
              <button
                v-if="s.acme_enabled" type="button"
                class="btn btn-sm" :disabled="issuing === s.id"
                :title="t('sites.getCertHint')"
                @click="issueCert(s)"
              >{{ issuing === s.id ? t('sites.getCertBusy') : t('sites.getCert') }}</button>
              <button
                v-if="s.auth_enabled" type="button"
                class="btn btn-sm"
                :title="t('sites.auth.manageHint')"
                @click="openAccounts(s)"
              ><Icon name="users" />{{ t('sites.auth.manage') }}</button>
              <button type="button" class="btn btn-sm" @click="openEdit(s)">{{ t('common.edit') }}</button>
              <button type="button" class="btn btn-sm btn-danger" @click="remove(s)">{{ t('common.delete') }}</button>
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

    <div class="divider"></div>

    <div class="field">
      <label class="label">{{ t('geo.title') }}</label>
      <select v-model="form.geo_mode" class="select">
        <option value="">{{ t('geo.modeInherit') }}</option>
        <option value="off">{{ t('geo.modeOff') }}</option>
        <option value="block">{{ t('geo.modeBlock') }}</option>
        <option value="allow">{{ t('geo.modeAllow') }}</option>
      </select>
      <div v-if="form.geo_mode === ''" class="hint">
        {{ globalGeoSummary ? t('geo.inheritHint', { rule: globalGeoSummary }) : t('geo.inheritHintPlain') }}
      </div>
      <div v-else-if="form.geo_mode === 'off'" class="hint">{{ t('geo.siteOffHint') }}</div>
    </div>

    <template v-if="form.geo_mode === 'block' || form.geo_mode === 'allow'">
      <div v-if="geo && !geo.ready" class="alert alert-warn" style="margin-bottom:12px">
        <Icon name="clock" />
        <div class="alert-body"><b>{{ t('geo.notReady') }}</b> {{ t('geo.notReadyHint') }}</div>
      </div>

      <div v-if="form.geo_mode === 'allow' && !form.geo_countries.length" class="alert alert-critical" style="margin-bottom:12px">
        <Icon name="alert" />
        <div class="alert-body"><b>{{ t('geo.allowEmptySite') }}</b> {{ t('geo.allowEmptySiteHint') }}</div>
      </div>
      <div v-else-if="form.geo_mode === 'allow'" class="alert alert-warn" style="margin-bottom:12px">
        <Icon name="info" />
        <div class="alert-body">{{ t('geo.allowCrawlers') }}</div>
      </div>

      <div class="field">
        <label class="label">{{ form.geo_mode === 'allow' ? t('geo.listAllow') : t('geo.listBlock') }}</label>
        <CountryPicker
          v-model="form.geo_countries"
          :countries="geo?.countries || []"
          :disabled="!geo?.ready"
        />
      </div>

      <ul class="geo-notes">
        <li>{{ t('geo.noteUnknown') }}</li>
        <li>{{ t('geo.noteCrawlers') }}</li>
        <li>{{ t('geo.noteAction') }}</li>
      </ul>
    </template>

    <div class="divider"></div>

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

    <div class="divider"></div>

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

    <div v-if="editing && editing.acme_last_error" class="alert alert-critical" style="margin-bottom:14px">
      <Icon name="alert" />
      <div class="alert-body">{{ t('sites.form.acmeLastError', { error: editing.acme_last_error }) }}</div>
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
    <div v-if="form.auth_enabled && canGate(form) && !editing" class="hint warn" style="margin-top:8px">
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

    <div v-if="!accounts.length" class="empty compact">
      <Icon name="users" />
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
            <td class="sub">{{ new Date(u.created_at).toLocaleDateString() }}</td>
            <td class="actions">
              <button type="button" class="btn btn-sm" @click="resetPassword(u)">{{ t('sites.auth.reset') }}</button>
              <button type="button" class="btn btn-sm" @click="revokeAccount(u)">{{ t('sites.auth.revoke') }}</button>
              <button type="button" class="btn btn-sm btn-danger" @click="deleteAccount(u)">{{ t('common.delete') }}</button>
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
      type="button" class="btn btn-primary"
      :disabled="accountsBusy || !newAccount.username || !newAccount.password"
      @click="addAccount"
    ><Icon name="plus" />{{ t('sites.auth.add') }}</button>
  </Modal>
</template>

<style scoped>
.skel-rows { display: flex; flex-direction: column; gap: 14px; padding: 8px 0; }
.site-name { font-weight: 600; }
.geo-notes { margin: 0 0 14px; padding-left: 18px; color: var(--ink-2); font-size: 12.5px; line-height: 1.6; }
.geo-notes li + li { margin-top: 4px; }
.table td:first-child { min-width: 150px; }
</style>
