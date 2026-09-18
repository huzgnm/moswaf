<script setup>
import { ref, computed, onMounted } from 'vue'
import { api, notify } from '../api'
import { t } from '../i18n'
import Modal from '../components/Modal.vue'
import Icon from '../components/Icon.vue'

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
const enabledCount = computed(() => rules.value.filter((r) => r.enabled).length)

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
  <div class="page-head">
    <div>
      <h2>{{ t('rules.title') }}</h2>
      <p class="page-sub">{{ t('rules.sub') }}</p>
    </div>
    <div class="page-actions">
      <span v-if="!loading" class="sub">{{ t('rules.count', { on: enabledCount, total: rules.length }) }}</span>
      <button type="button" class="btn btn-primary" @click="openCreate"><Icon name="plus" />{{ t('rules.addButton') }}</button>
    </div>
  </div>

  <div class="filter-bar">
    <div class="grow search">
      <Icon name="search" />
      <input v-model="filter" class="input" :placeholder="t('rules.search')" />
    </div>
    <select v-model="category" class="select" style="width:200px" :aria-label="t('rules.col.category')">
      <option value="">{{ t('rules.allCategories') }}</option>
      <option v-for="c in categories" :key="c" :value="c">{{ c }}</option>
    </select>
  </div>

  <div class="card">
    <div v-if="loading" class="skel-rows"><div v-for="i in 8" :key="i" class="skel skel-line"></div></div>
    <div v-else-if="!shown.length" class="empty">
      <Icon name="rules" />
      <b>{{ t('rules.noMatch') }}</b>
    </div>
    <div v-else class="table-wrap">
      <table class="table">
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
          <tr v-for="r in shown" :key="r.id" :class="{ 'is-off': !r.enabled }">
            <td>
              <label class="switch">
                <input type="checkbox" :checked="r.enabled" @change="toggle(r)" />
                <span class="track"></span>
                <span class="sr-only">{{ r.name }}</span>
              </label>
            </td>
            <td>
              <div>{{ r.name }}</div>
              <div class="mono dim" style="font-size:11.5px">{{ r.id }}<span v-if="r.builtin"> · {{ t('rules.builtin') }}</span></div>
            </td>
            <td><span class="tag">{{ r.category }}</span></td>
            <td class="sub">{{ targetLabel(r.target) }}</td>
            <td>
              <span class="tag" :class="`tag-${r.action}`">
                <span class="dot"></span>{{ actionLabel(r.action) }}
              </span>
            </td>
            <td><span class="tag" :class="`tag-${r.severity}`">{{ severityLabel(r.severity) }}</span></td>
            <td class="actions">
              <button type="button" class="btn btn-sm" @click="openEdit(r)">{{ t('common.edit') }}</button>
              <button v-if="!r.builtin" type="button" class="btn btn-sm btn-danger" @click="remove(r)">{{ t('common.delete') }}</button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
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

<style scoped>
.search { position: relative; }
.search .ico { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); width: 15px; height: 15px; color: var(--ink-3); pointer-events: none; }
.search .input { padding-left: 32px; }
.skel-rows { display: flex; flex-direction: column; gap: 14px; padding: 8px 0; }
tr.is-off td:not(:first-child) { opacity: .55; }
</style>
