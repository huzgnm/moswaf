<script setup>
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { api, setToken, session } from '../api'
import { t, applyCountryLocale } from '../i18n'
import LanguagePicker from '../components/LanguagePicker.vue'
import Logo from '../components/Logo.vue'
import Icon from '../components/Icon.vue'

const router = useRouter()
const username = ref('admin')
const password = ref('')
const error = ref('')
const busy = ref(false)
const showPassword = ref(false)
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
    applyCountryLocale(res.user)
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
    <!-- A network grid, one step above invisible. It sits behind the card and
         is masked away before it reaches the form. -->
    <div class="grid-bg" aria-hidden="true"></div>

    <main class="login-col">
      <div class="login-brand">
        <Logo :size="30" />
        <span class="wordmark">MosWAF</span>
      </div>

      <h1 class="login-title">{{ t('login.heading') }}</h1>
      <p class="login-lede">{{ t('login.lede') }}</p>

      <form class="login-card" @submit.prevent="submit">
        <div class="field">
          <label class="label" for="login-user">{{ t('login.username') }}</label>
          <input id="login-user" ref="userInput" v-model="username" class="input" autocomplete="username" />
        </div>

        <div class="field">
          <label class="label" for="login-pass">{{ t('login.password') }}</label>
          <div class="pass">
            <input
              id="login-pass" v-model="password" class="input"
              :type="showPassword ? 'text' : 'password'" autocomplete="current-password"
            />
            <button
              type="button" class="reveal"
              :aria-label="showPassword ? t('login.hidePassword') : t('login.showPassword')"
              :aria-pressed="showPassword ? 'true' : 'false'"
              @click="showPassword = !showPassword"
            ><Icon name="eye" /></button>
          </div>
        </div>

        <!-- Reserved height: an error appearing must not push the button down -->
        <div class="error-slot" role="alert" aria-live="polite">
          <div v-if="error" class="alert alert-critical">
            <Icon name="alert" />
            <div class="alert-body">{{ error }}</div>
          </div>
        </div>

        <button class="btn btn-primary login-btn" :disabled="busy">
          {{ busy ? t('login.submitting') : t('login.submit') }}
        </button>
      </form>

      <div class="login-foot">
        <span class="eyebrow">{{ t('login.footNote') }}</span>
        <LanguagePicker />
      </div>
    </main>
  </div>
</template>

<style scoped>
.login-wrap {
  min-height: 100vh; display: flex; align-items: center; justify-content: center;
  padding: 32px 20px; position: relative; overflow: hidden; background: var(--bg);
}
.grid-bg {
  position: absolute; inset: 0; pointer-events: none;
  background-image:
    linear-gradient(var(--line) 1px, transparent 1px),
    linear-gradient(90deg, var(--line) 1px, transparent 1px);
  background-size: 72px 72px; opacity: .6;
  -webkit-mask-image: radial-gradient(ellipse 70% 60% at 50% 45%, transparent 38%, rgba(0,0,0,.75));
  mask-image: radial-gradient(ellipse 70% 60% at 50% 45%, transparent 38%, rgba(0,0,0,.75));
}

.login-col { position: relative; width: min(94vw, 396px); }

.login-brand { display: flex; align-items: center; gap: 10px; margin-bottom: 30px; }
.wordmark { font-size: 17px; font-weight: 700; letter-spacing: -.02em; color: var(--ink); }

.login-title { font-size: 25px; font-weight: 600; letter-spacing: -.035em; }
.login-lede { color: var(--ink-2); font-size: 13.5px; margin: 8px 0 24px; line-height: 1.6; }

.login-card {
  background: var(--surface); border: 1px solid var(--line);
  border-radius: var(--radius-card); padding: 24px; box-shadow: var(--shadow);
}
.login-card .field:last-of-type { margin-bottom: 0; }

.pass { position: relative; }
.pass .input { padding-right: 38px; }
.reveal {
  position: absolute; right: 4px; top: 50%; transform: translateY(-50%);
  width: 28px; height: 28px; display: inline-flex; align-items: center; justify-content: center;
  background: none; border: none; color: var(--ink-3); border-radius: var(--radius);
}
.reveal:hover { color: var(--ink); background: var(--surface-2); }
.reveal .ico { width: 15px; height: 15px; }
.reveal[aria-pressed="true"] { color: var(--ink); }

.error-slot { min-height: 16px; margin: 14px 0; }
.login-btn { width: 100%; padding: 10px 14px; }

.login-foot { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-top: 20px; }

@media (max-width: 420px) {
  .login-title { font-size: 22px; }
  .login-foot { flex-direction: column; align-items: flex-start; }
}
</style>
