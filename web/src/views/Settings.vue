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
    notify('Da luu va ap cau hinh xuong data plane')
  } catch (e) {
    notify(e.message, true)
  } finally {
    busy.value = false
  }
}

async function changePassword() {
  if (pwd.value.next !== pwd.value.confirm) {
    notify('Hai o mat khau moi khong khop', true)
    return
  }
  pwdBusy.value = true
  try {
    await api.post('/api/auth/password', { current: pwd.value.current, new: pwd.value.next })
    pwd.value = { current: '', next: '', confirm: '' }
    notify('Da doi mat khau')
  } catch (e) {
    notify(e.message, true)
  } finally {
    pwdBusy.value = false
  }
}

async function republish() {
  try {
    const res = await api.post('/api/system/publish')
    notify(`Da day lai toan bo cau hinh (phien ban ${res.version})`)
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
          <div class="card-title">Chinh sach toan cuc</div>
          <div class="card-sub">Ap cho moi site khong tu dat rieng</div>
        </div>
        <button class="btn btn-primary" :disabled="busy" @click="save">
          {{ busy ? 'Dang luu...' : 'Luu thay doi' }}
        </button>
      </div>

      <div class="grid grid-2">
        <div class="field">
          <label class="label">Che do mac dinh</label>
          <select v-model="settings.default_mode" class="select">
            <option value="protect">Bao ve - chan that</option>
            <option value="monitor">Chi theo doi - ghi log, khong chan</option>
            <option value="off">Tat</option>
          </select>
        </div>
        <div class="field">
          <label class="label">Ma tra ve khi chan</label>
          <input v-model="settings.block_status" type="number" class="input mono" />
          <div class="hint">403 la mac dinh. Dung 444 neu muon cat ket noi khong tra loi gi.</div>
        </div>

        <div class="field">
          <label class="label">Gioi han request/giay moi IP</label>
          <input v-model="settings.global_rate_rps" type="number" class="input mono" />
        </div>
        <div class="field">
          <label class="label">Gioi han trong cua so 10 giay</label>
          <input v-model="settings.global_rate_burst" type="number" class="input mono" />
          <div class="hint">Bat ke tan cong rai deu de ne nguong theo giay.</div>
        </div>

        <div class="field">
          <label class="label">Thoi gian ban tam thoi (giay)</label>
          <input v-model="settings.ban_seconds" type="number" class="input mono" />
          <div class="hint">Ap dung sau 3 lan vuot nguong trong 1 phut.</div>
        </div>
        <div class="field">
          <label class="label">Do kho JS challenge (so bit)</label>
          <input v-model="settings.challenge_difficulty" type="number" class="input mono" min="8" max="24" />
          <div class="hint">
            16 bit ≈ 0,1-0,3 giay tren may khach. Moi bit tang gap doi cong suc.
            Chi nang len 18-20 khi dang bi flood nang.
          </div>
        </div>

        <div class="field">
          <label class="label">Cookie challenge song bao lau (giay)</label>
          <input v-model="settings.challenge_ttl" type="number" class="input mono" />
        </div>
        <div class="field">
          <label class="label">Kich thuoc body toi da duoc quet (byte)</label>
          <input v-model="settings.max_body_scan" type="number" class="input mono" />
        </div>

        <div class="field">
          <label class="label">Header chua IP that</label>
          <select v-model="settings.real_ip_header" class="select">
            <option value="">Khong dung - lay IP ket noi truc tiep</option>
            <option value="X-Forwarded-For">X-Forwarded-For</option>
            <option value="CF-Connecting-IP">CF-Connecting-IP (Cloudflare)</option>
            <option value="X-Real-IP">X-Real-IP</option>
          </select>
          <div class="hint">Chi bat khi co CDN/proxy dung truoc MosWAF, neu khong ke tan cong se gia mao IP.</div>
        </div>
        <div class="field">
          <label class="label">Proxy tin cay (cach nhau bang dau phay)</label>
          <input v-model="proxies" class="input mono" placeholder="173.245.48.0/20, 103.21.244.0/22" />
          <div class="hint">De trong nghia la tin moi nguon - chi nen lam khi MosWAF khong lo ra internet.</div>
        </div>

        <div class="field">
          <label class="label">Giu nhat ky tan cong (ngay)</label>
          <input v-model="settings.log_retain_days" type="number" class="input mono" />
        </div>
        <div class="field" style="display:flex; flex-direction:column; gap:12px; justify-content:center">
          <label class="switch">
            <input v-model="settings.scan_body" type="checkbox" />
            <span class="track"></span>
            <span>Quet noi dung POST</span>
          </label>
          <label class="switch">
            <input v-model="settings.log_allowed" type="checkbox" />
            <span class="track"></span>
            <span>Ghi log ca request binh thuong (rat ton dung luong)</span>
          </label>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-title">Doi mat khau quan tri</div>
      </div>
      <div class="grid grid-2">
        <div class="field">
          <label class="label">Mat khau hien tai</label>
          <input v-model="pwd.current" type="password" class="input" autocomplete="current-password" />
        </div>
        <div></div>
        <div class="field">
          <label class="label">Mat khau moi</label>
          <input v-model="pwd.next" type="password" class="input" autocomplete="new-password" />
        </div>
        <div class="field">
          <label class="label">Nhap lai mat khau moi</label>
          <input v-model="pwd.confirm" type="password" class="input" autocomplete="new-password" />
        </div>
      </div>
      <button class="btn" :disabled="pwdBusy" @click="changePassword">Doi mat khau</button>
    </div>

    <div class="card">
      <div class="card-head">
        <div>
          <div class="card-title">Bao tri</div>
          <div class="card-sub">Day lai toan bo cau hinh xuong OpenResty neu nghi data plane bi lech</div>
        </div>
        <button class="btn" @click="republish">Dong bo lai data plane</button>
      </div>
    </div>
  </div>

  <div v-else class="empty">Dang tai cai dat...</div>
</template>
