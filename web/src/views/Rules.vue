<script setup>
import { ref, computed, onMounted } from 'vue'
import { api, notify } from '../api'
import Modal from '../components/Modal.vue'

const rules = ref([])
const loading = ref(true)
const filter = ref('')
const category = ref('')
const showForm = ref(false)
const busy = ref(false)
const editing = ref(null)
const form = ref(blank())

function blank() {
  return {
    name: '',
    category: 'custom',
    target: 'any',
    pattern: '',
    action: 'deny',
    severity: 'medium',
  }
}

const ACTION_LABELS = {
  deny: 'Block',
  challenge: 'Challenge',
  ban: 'Ban IP',
  log: 'Log only',
}
const SEVERITY_LABELS = {
  low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical',
}
const TARGET_LABELS = {
  any: 'Whole request', uri: 'Path', args: 'Query string',
  body: 'POST body', ua: 'User-Agent', header: 'Headers', cookie: 'Cookies',
}

const categories = computed(() => [...new Set(rules.value.map((r) => r.category))].sort())

const shown = computed(() => rules.value.filter((r) => {
  if (category.value && r.category !== category.value) return false
  if (!filter.value) return true
  const q = filter.value.toLowerCase()
  return r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || r.pattern.toLowerCase().includes(q)
}))

async function load() {
  loading.value = true
  try {
    rules.value = await api.list('/api/rules')
  } catch (e) {
    notify(e.message, true)
  } finally {
    loading.value = false
  }
}

async function toggle(rule) {
  const next = !rule.enabled
  try {
    await api.post(`/api/rules/${rule.id}/toggle`, { enabled: next })
    rule.enabled = next
    notify(next ? `Rule "${rule.name}" enabled` : `Rule "${rule.name}" disabled`)
  } catch (e) {
    notify(e.message, true)
  }
}

function openCreate() {
  editing.value = null
  form.value = blank()
  showForm.value = true
}

function openEdit(rule) {
  editing.value = rule
  form.value = { ...rule }
  showForm.value = true
}

async function save() {
  busy.value = true
  try {
    if (editing.value) {
      await api.put(`/api/rules/${editing.value.id}`, form.value)
      notify('Rule updated')
    } else {
      await api.post('/api/rules', form.value)
      notify('Rule added')
    }
    showForm.value = false
    await load()
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

async function remove(rule) {
  if (!confirm(`Delete rule "${rule.name}"?`)) return
  try {
    await api.del(`/api/rules/${rule.id}`)
    notify('Rule deleted')
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
        <div class="card-title">Detection rules</div>
        <div class="card-sub">
          Built-in rules ship with MosWAF. Custom rules are scanned alongside them, in table order.
        </div>
      </div>
      <button class="btn btn-primary" @click="openCreate">Add rule</button>
    </div>

    <div class="row" style="margin-bottom:14px">
      <input v-model="filter" class="input grow" placeholder="Search by name, id or pattern" />
      <select v-model="category" class="select" style="width:180px">
        <option value="">All categories</option>
        <option v-for="c in categories" :key="c" :value="c">{{ c }}</option>
      </select>
    </div>

    <div v-if="loading" class="empty">Loading...</div>
    <table v-else class="table">
      <thead>
        <tr>
          <th style="width:52px">On</th>
          <th>Name</th>
          <th>Category</th>
          <th>Scans</th>
          <th>Action</th>
          <th>Severity</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="r in shown" :key="r.id">
          <td>
            <label class="switch">
              <input type="checkbox" :checked="r.enabled" @change="toggle(r)" />
              <span class="track"></span>
            </label>
          </td>
          <td>
            <div>{{ r.name }}</div>
            <div class="mono" style="color:var(--text-muted); font-size:11.5px">{{ r.id }}</div>
          </td>
          <td><span class="tag">{{ r.category }}</span></td>
          <td class="card-sub">{{ TARGET_LABELS[r.target] || r.target }}</td>
          <td>
            <span class="tag" :class="`tag-${r.action === 'ban' ? 'deny' : r.action}`">
              <span class="dot"></span>{{ ACTION_LABELS[r.action] || r.action }}
            </span>
          </td>
          <td class="card-sub">{{ SEVERITY_LABELS[r.severity] || r.severity }}</td>
          <td style="text-align:right; white-space:nowrap">
            <button class="btn btn-sm" @click="openEdit(r)">Edit</button>
            <button v-if="!r.builtin" class="btn btn-sm btn-danger" style="margin-left:6px" @click="remove(r)">
              Delete
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <Modal
    v-if="showForm"
    :title="editing ? `Edit rule: ${editing.name}` : 'Add a rule'"
    :busy="busy"
    @close="showForm = false"
    @submit="save"
  >
    <div class="field">
      <label class="label">Rule name</label>
      <input v-model="form.name" class="input" placeholder="Block external access to /admin" />
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Category</label>
        <input v-model="form.category" class="input" />
      </div>
      <div class="field grow">
        <label class="label">Where to scan</label>
        <select v-model="form.target" class="select">
          <option v-for="(label, key) in TARGET_LABELS" :key="key" :value="key">{{ label }}</option>
        </select>
      </div>
    </div>

    <div class="field">
      <label class="label">Regular expression (PCRE)</label>
      <textarea v-model="form.pattern" class="input" placeholder="(?i)/admin/(config|backup)"></textarea>
      <div class="hint">
        Prefix with <code class="mono">(?i)</code> to make it case-insensitive.
        Avoid lookahead and backreferences so the pattern stays fast in the data plane.
      </div>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Action on match</label>
        <select v-model="form.action" class="select">
          <option v-for="(label, key) in ACTION_LABELS" :key="key" :value="key">{{ label }}</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">Severity</label>
        <select v-model="form.severity" class="select">
          <option v-for="(label, key) in SEVERITY_LABELS" :key="key" :value="key">{{ label }}</option>
        </select>
      </div>
    </div>
  </Modal>
</template>
