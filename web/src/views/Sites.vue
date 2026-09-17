<script setup>
import { ref, onMounted } from 'vue'
import { api, notify } from '../api'
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
    tls_cert: '',
    tls_key: '',
  }
}

const MODE_LABELS = {
  protect: 'Protect',
  monitor: 'Monitor only',
  off: 'Off',
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
      notify('Site updated; the configuration is being pushed to the data plane')
    } else {
      await api.post('/api/sites', payload)
      notify('Site added. Point the domain\'s DNS at this machine to start filtering.')
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
  if (!confirm(`Delete site "${site.name}"? Traffic to this domain will no longer pass through MosWAF.`)) return
  try {
    await api.del(`/api/sites/${site.id}`)
    notify('Site deleted')
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
        <div class="card-title">Protected sites</div>
        <div class="card-sub">Each site is a group of domains pointing at one upstream behind it</div>
      </div>
      <button class="btn btn-primary" @click="openCreate">Add site</button>
    </div>

    <div v-if="loading" class="empty">Loading...</div>
    <div v-else-if="!sites.length" class="empty">
      No sites yet. Click "Add site" to put your first domain behind MosWAF.
    </div>

    <table v-else class="table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Domains</th>
          <th>Upstream</th>
          <th>Mode</th>
          <th>Rate limit</th>
          <th>HTTPS</th>
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
              <span class="dot"></span>{{ MODE_LABELS[s.mode] }}
            </span>
          </td>
          <td class="mono">
            {{ s.rate_rps ? `${s.rate_rps} r/s` : 'default' }}
          </td>
          <td>
            <span class="tag" :class="s.has_tls ? 'tag-ok' : 'tag-off'">
              <span class="dot"></span>{{ s.has_tls ? (s.force_https ? 'Forced' : 'Certificate') : 'None' }}
            </span>
          </td>
          <td style="text-align:right; white-space:nowrap">
            <button class="btn btn-sm" @click="openEdit(s)">Edit</button>
            <button class="btn btn-sm btn-danger" style="margin-left:6px" @click="remove(s)">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <Modal
    v-if="showForm"
    :title="editing ? `Edit site: ${editing.name}` : 'Add a site'"
    :busy="busy"
    @close="showForm = false"
    @submit="save"
  >
    <div class="field">
      <label class="label">Display name</label>
      <input v-model="form.name" class="input" placeholder="Online store" />
    </div>

    <div class="field">
      <label class="label">Domains (comma separated)</label>
      <input v-model="form.domains" class="input mono" placeholder="example.com, www.example.com" />
      <div class="hint">Point the A record of these domains at the machine running MosWAF.</div>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Upstream scheme</label>
        <select v-model="form.upstream_scheme" class="select">
          <option value="http">http</option>
          <option value="https">https</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">Upstream host</label>
        <input v-model="form.upstream_host" class="input mono" placeholder="10.0.0.5 or host.docker.internal" />
      </div>
      <div class="field" style="width:110px">
        <label class="label">Port</label>
        <input v-model="form.upstream_port" type="number" class="input mono" />
      </div>
    </div>
    <div class="hint" style="margin:-8px 0 14px">
      To reach an app running on this same host, use
      <code class="mono">host.docker.internal</code>.
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Protection mode</label>
        <select v-model="form.mode" class="select">
          <option value="protect">Protect - actually block</option>
          <option value="monitor">Monitor only - log, never block</option>
          <option value="off">Off - let everything through</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">JS challenge</label>
        <select v-model="form.challenge" class="select">
          <option value="auto">Automatic - only when suspicious</option>
          <option value="always">Always on - every unknown visitor must solve it</option>
          <option value="off">Off</option>
        </select>
      </div>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Requests per second per IP</label>
        <input v-model="form.rate_rps" type="number" class="input mono" />
        <div class="hint">0 = use the global value from Settings</div>
      </div>
      <div class="field grow">
        <label class="label">Limit over 10 seconds</label>
        <input v-model="form.rate_burst" type="number" class="input mono" />
      </div>
    </div>

    <div class="field">
      <label class="label">TLS certificate (PEM)</label>
      <textarea
        v-model="form.tls_cert" class="input"
        :placeholder="editing && editing.has_tls ? 'Leave empty to keep the current certificate' : '-----BEGIN CERTIFICATE-----'"
      ></textarea>
    </div>
    <div class="field">
      <label class="label">Private key (PEM)</label>
      <textarea
        v-model="form.tls_key" class="input"
        :placeholder="editing && editing.has_tls ? 'Leave empty to keep the current key' : '-----BEGIN PRIVATE KEY-----'"
      ></textarea>
    </div>

    <label class="switch">
      <input v-model="form.force_https" type="checkbox" />
      <span class="track"></span>
      <span>Redirect all HTTP traffic to HTTPS</span>
    </label>
  </Modal>
</template>
