<script setup>
import { ref, computed, onMounted } from 'vue'
import { api, notify } from '../api'
import { t } from '../i18n'
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

// The keys are the values the API uses; the labels are resolved at render time
// so a language change repaints the table and both dropdowns.
const ACTIONS = ['deny', 'challenge', 'ban', 'log']
const SEVERITIES = ['low', 'medium', 'high', 'critical']
const TARGETS = ['any', 'uri', 'args', 'body', 'ua', 'header', 'cookie']

const actionLabel = (a) => t(`rules.action.${a}`)
const severityLabel = (sev) => t(`severity.${sev}`)
const targetLabel = (target) => t(`rules.target.${target}`)

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
    notify(t(next ? 'rules.enabled' : 'rules.disabled', { name: rule.name }))
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
      notify(t('rules.updated'))
    } else {
      await api.post('/api/rules', form.value)
      notify(t('rules.created'))
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
  if (!confirm(t('rules.deleteConfirm', { name: rule.name }))) return
  try {
    await api.del(`/api/rules/${rule.id}`)
    notify(t('rules.deleted'))
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
        <div class="card-title">{{ t('rules.title') }}</div>
        <div class="card-sub">{{ t('rules.sub') }}</div>
      </div>
      <button class="btn btn-primary" @click="openCreate">{{ t('rules.addButton') }}</button>
    </div>

    <div class="row" style="margin-bottom:14px">
      <input v-model="filter" class="input grow" :placeholder="t('rules.search')" />
      <select v-model="category" class="select" style="width:180px">
        <option value="">{{ t('rules.allCategories') }}</option>
        <option v-for="c in categories" :key="c" :value="c">{{ c }}</option>
      </select>
    </div>

    <div v-if="loading" class="empty">{{ t('common.loading') }}</div>
    <table v-else class="table">
      <thead>
        <tr>
          <th style="width:52px">{{ t('rules.col.on') }}</th>
          <th>{{ t('rules.col.name') }}</th>
          <th>{{ t('rules.col.category') }}</th>
          <th>{{ t('rules.col.scans') }}</th>
          <th>{{ t('rules.col.action') }}</th>
          <th>{{ t('rules.col.severity') }}</th>
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
          <td class="card-sub">{{ targetLabel(r.target) }}</td>
          <td>
            <span class="tag" :class="`tag-${r.action === 'ban' ? 'deny' : r.action}`">
              <span class="dot"></span>{{ actionLabel(r.action) }}
            </span>
          </td>
          <td class="card-sub">{{ severityLabel(r.severity) }}</td>
          <td style="text-align:right; white-space:nowrap">
            <button class="btn btn-sm" @click="openEdit(r)">{{ t('common.edit') }}</button>
            <button v-if="!r.builtin" class="btn btn-sm btn-danger" style="margin-left:6px" @click="remove(r)">
              {{ t('common.delete') }}
            </button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <Modal
    v-if="showForm"
    :title="editing ? t('rules.form.editTitle', { name: editing.name }) : t('rules.form.addTitle')"
    :busy="busy"
    @close="showForm = false"
    @submit="save"
  >
    <div class="field">
      <label class="label">{{ t('rules.form.name') }}</label>
      <input v-model="form.name" class="input" :placeholder="t('rules.form.namePlaceholder')" />
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">{{ t('rules.form.category') }}</label>
        <input v-model="form.category" class="input" />
      </div>
      <div class="field grow">
        <label class="label">{{ t('rules.form.target') }}</label>
        <select v-model="form.target" class="select">
          <option v-for="key in TARGETS" :key="key" :value="key">{{ targetLabel(key) }}</option>
        </select>
      </div>
    </div>

    <div class="field">
      <label class="label">{{ t('rules.form.pattern') }}</label>
      <textarea v-model="form.pattern" class="input" placeholder="(?i)/admin/(config|backup)"></textarea>
      <div class="hint">{{ t('rules.form.patternHint', { code: '(?i)' }) }}</div>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">{{ t('rules.form.action') }}</label>
        <select v-model="form.action" class="select">
          <option v-for="key in ACTIONS" :key="key" :value="key">{{ actionLabel(key) }}</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">{{ t('rules.form.severity') }}</label>
        <select v-model="form.severity" class="select">
          <option v-for="key in SEVERITIES" :key="key" :value="key">{{ severityLabel(key) }}</option>
        </select>
      </div>
    </div>
  </Modal>
</template>
