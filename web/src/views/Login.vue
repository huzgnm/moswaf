<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, setToken, session } from '../api'
import { t } from '../i18n'
import LanguagePicker from '../components/LanguagePicker.vue'

const router = useRouter()
const username = ref('admin')
const password = ref('')
const error = ref('')
const busy = ref(false)
const userInput = ref(null)

onMounted(() => userInput.value?.focus())

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const res = await api.post('/api/auth/login', {
      username: username.value,
      password: password.value,
    })
    setToken(res.token)
    session.user = res.user
    router.push('/')
  } catch (e) {
    error.value = e.message
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="login-wrap">
    <form class="login-card" @submit.prevent="submit">
      <div class="brand-big">Mos<b>WAF</b></div>
      <p class="card-sub" style="margin:0 0 22px">{{ t('app.tagline') }}</p>

      <div class="field">
        <label class="label">{{ t('login.username') }}</label>
        <input ref="userInput" v-model="username" class="input" autocomplete="username" />
      </div>
      <div class="field">
        <label class="label">{{ t('login.password') }}</label>
        <input v-model="password" type="password" class="input" autocomplete="current-password" />
      </div>

      <div v-if="error" class="login-error">{{ error }}</div>

      <button class="btn btn-primary" style="width:100%; justify-content:center" :disabled="busy">
        {{ busy ? t('login.submitting') : t('login.submit') }}
      </button>

      <div class="login-lang">
        <LanguagePicker />
      </div>
    </form>
  </div>
</template>

<style scoped>
.login-wrap {
  min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
}
.login-card {
  width: min(94vw, 380px); background: var(--surface-1);
  border: 1px solid var(--line); border-radius: 14px; padding: 32px 28px;
  box-shadow: var(--shadow);
}
.brand-big {
  font-size: 20px; letter-spacing: .16em; text-transform: uppercase;
  color: var(--text-secondary); margin-bottom: 6px;
}
.brand-big b { color: var(--series-1); }
.login-lang { display: flex; justify-content: center; margin-top: 18px; }
.login-error {
  background: #2a1616; border: 1px solid #5a2a2a; color: #f0a0a0;
  padding: 9px 12px; border-radius: 8px; font-size: 12.5px; margin-bottom: 14px;
}
</style>
