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
  protect: 'Bao ve',
  monitor: 'Chi theo doi',
  off: 'Tat',
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
      notify('Da cap nhat site, cau hinh dang duoc ap xuong data plane')
    } else {
      await api.post('/api/sites', payload)
      notify('Da them site. Tro DNS cua ten mien ve IP may nay de bat dau loc.')
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
  if (!confirm(`Xoa site "${site.name}"? Luu luong toi ten mien nay se khong con di qua MosWAF.`)) return
  try {
    await api.del(`/api/sites/${site.id}`)
    notify('Da xoa site')
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
        <div class="card-title">Trang web duoc bao ve</div>
        <div class="card-sub">Moi site la mot nhom ten mien tro ve mot upstream phia sau</div>
      </div>
      <button class="btn btn-primary" @click="openCreate">Them site</button>
    </div>

    <div v-if="loading" class="empty">Dang tai...</div>
    <div v-else-if="!sites.length" class="empty">
      Chua co site nao. Bam "Them site" de dua ten mien dau tien vao sau MosWAF.
    </div>

    <table v-else class="table">
      <thead>
        <tr>
          <th>Ten</th>
          <th>Ten mien</th>
          <th>Upstream</th>
          <th>Che do</th>
          <th>Gioi han</th>
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
            {{ s.rate_rps ? `${s.rate_rps} r/s` : 'mac dinh' }}
          </td>
          <td>
            <span class="tag" :class="s.has_tls ? 'tag-ok' : 'tag-off'">
              <span class="dot"></span>{{ s.has_tls ? (s.force_https ? 'Ep HTTPS' : 'Co chung chi') : 'Chua co' }}
            </span>
          </td>
          <td style="text-align:right; white-space:nowrap">
            <button class="btn btn-sm" @click="openEdit(s)">Sua</button>
            <button class="btn btn-sm btn-danger" style="margin-left:6px" @click="remove(s)">Xoa</button>
          </td>
        </tr>
      </tbody>
    </table>
  </div>

  <Modal
    v-if="showForm"
    :title="editing ? `Sua site: ${editing.name}` : 'Them site moi'"
    :busy="busy"
    @close="showForm = false"
    @submit="save"
  >
    <div class="field">
      <label class="label">Ten hien thi</label>
      <input v-model="form.name" class="input" placeholder="Website ban hang" />
    </div>

    <div class="field">
      <label class="label">Ten mien (cach nhau bang dau phay)</label>
      <input v-model="form.domains" class="input mono" placeholder="example.com, www.example.com" />
      <div class="hint">Tro ban ghi A cua cac ten mien nay ve IP may dang chay MosWAF.</div>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Giao thuc upstream</label>
        <select v-model="form.upstream_scheme" class="select">
          <option value="http">http</option>
          <option value="https">https</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">Dia chi upstream</label>
        <input v-model="form.upstream_host" class="input mono" placeholder="10.0.0.5 hoac host.docker.internal" />
      </div>
      <div class="field" style="width:110px">
        <label class="label">Cong</label>
        <input v-model="form.upstream_port" type="number" class="input mono" />
      </div>
    </div>
    <div class="hint" style="margin:-8px 0 14px">
      Muon tro ve web dang chay tren chinh may chu nay thi dung
      <code class="mono">host.docker.internal</code>.
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Che do bao ve</label>
        <select v-model="form.mode" class="select">
          <option value="protect">Bao ve - chan that</option>
          <option value="monitor">Chi theo doi - ghi log, khong chan</option>
          <option value="off">Tat - cho qua het</option>
        </select>
      </div>
      <div class="field grow">
        <label class="label">JS challenge</label>
        <select v-model="form.challenge" class="select">
          <option value="auto">Tu dong - chi khi nghi ngo</option>
          <option value="always">Luon bat - moi khach la deu phai giai</option>
          <option value="off">Tat</option>
        </select>
      </div>
    </div>

    <div class="row">
      <div class="field grow">
        <label class="label">Gioi han request/giay moi IP</label>
        <input v-model="form.rate_rps" type="number" class="input mono" />
        <div class="hint">0 = dung muc toan cuc trong Cai dat</div>
      </div>
      <div class="field grow">
        <label class="label">Gioi han trong 10 giay</label>
        <input v-model="form.rate_burst" type="number" class="input mono" />
      </div>
    </div>

    <div class="field">
      <label class="label">Chung chi TLS (PEM)</label>
      <textarea
        v-model="form.tls_cert" class="input"
        :placeholder="editing && editing.has_tls ? 'De trong de giu chung chi hien tai' : '-----BEGIN CERTIFICATE-----'"
      ></textarea>
    </div>
    <div class="field">
      <label class="label">Khoa rieng (PEM)</label>
      <textarea
        v-model="form.tls_key" class="input"
        :placeholder="editing && editing.has_tls ? 'De trong de giu khoa hien tai' : '-----BEGIN PRIVATE KEY-----'"
      ></textarea>
    </div>

    <label class="switch">
      <input v-model="form.force_https" type="checkbox" />
      <span class="track"></span>
      <span>Chuyen huong toan bo HTTP sang HTTPS</span>
    </label>
  </Modal>
</template>
