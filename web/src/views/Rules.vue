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
  deny: 'Chan',
  challenge: 'Bat challenge',
  ban: 'Ban IP',
  log: 'Chi ghi log',
}
const SEVERITY_LABELS = {
  low: 'Thap', medium: 'Trung binh', high: 'Cao', critical: 'Nghiem trong',
}
const TARGET_LABELS = {
  any: 'Toan bo request', uri: 'Duong dan', args: 'Tham so URL',
  body: 'Noi dung POST', ua: 'User-Agent', header: 'Header', cookie: 'Cookie',
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
    notify(next ? `Da bat luat "${rule.name}"` : `Da tat luat "${rule.name}"`)
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
      notify('Da cap nhat luat')
    } else {
      await api.post('/api/rules', form.value)
      notify('Da them luat moi')
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
  if (!confirm(`Xoa luat "${rule.name}"?`)) return
  try {
    await api.del(`/api/rules/${rule.id}`)
    notify('Da xoa luat')
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
        <div class="card-title">Luat phat hien</div>
        <div class="card-sub">
          Luat goc di kem san. Luat tu tao duoc quet cung luc, theo dung thu tu trong bang.
        </div>
      </div>
      <button class="btn btn-primary" @click="openCreate">Them luat</button>
    </div>

    <div class="row" style="margin-bottom:14px">
      <input v-model="filter" class="input grow" placeholder="Tim theo ten, ma hoac bieu thuc" />
      <select v-model="category" class="select" style="width:180px">
        <option value="">Tat ca nhom</option>
        <option v-for="c in categories" :key="c" :value="c">{{ c }}</option>
      </select>
    </div>

    <div v-if="loading" class="empty">Dang tai...</div>
    <table v-else class="table">
      <thead>
        <tr>
          <th style="width:52px">Bat</th>
          <th>Ten</th>
          <th>Nhom</th>
          <th>Quet o</th>
          <th>Hanh dong</th>
          <th>Muc do</th>
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
            <button class="btn btn-sm" @click="openEdit(r)">Sua</button>
            <button v-if="!r.builtin" class="btn btn-sm btn-danger" style="margin-left:6px" @click="remove(r)">
              Xoa
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <Modal
    v-if="showForm"
    :title="editing ? `Sua luat: ${editing.name}` : 'Them luat moi'"
    :busy="busy"
    @close="showForm = false"
    @submit="save"
  >
    <div class="field">
      <label class="label">Ten luat</label>
      <input v-model="form.name" class="input" placeholder="Chan truy cap /admin tu ngoai" />
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Nhom</label>
        <input v-model="form.category" class="input" />
      </div>
      <div class="field grow">
        <label class="label">Quet o dau</label>
        <select v-model="form.target" class="select">
          <option v-for="(label, key) in TARGET_LABELS" :key="key" :value="key">{{ label }}</option>
        </select>
      </div>
    </div>

    <div class="field">
      <label class="label">Bieu thuc chinh quy (PCRE)</label>
      <textarea v-model="form.pattern" class="input" placeholder="(?i)/admin/(config|backup)"></textarea>
      <div class="hint">
        Dung <code class="mono">(?i)</code> o dau de khong phan biet hoa thuong.
        Tranh lookahead/backreference de bieu thuc chay nhanh o data plane.
      </div>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Hanh dong khi khop</label>
        <select v-model="form.action" class="select">
          <option v-for="(label, key) in ACTION_LABELS" :key="key" :value="key">{{ label }}</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">Muc do</label>
        <select v-model="form.severity" class="select">
          <option v-for="(label, key) in SEVERITY_LABELS" :key="key" :value="key">{{ label }}</option>
        </select>
      </div>
    </div>
  </Modal>
</template>
