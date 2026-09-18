// Interface translations.
//
// Deliberately hand-rolled rather than pulling in vue-i18n: the dashboard needs
// lookup, one level of {placeholder} interpolation and a fallback, which is the
// code below, and the project keeps its runtime dependencies to vue and
// vue-router on purpose.
//
// Keys are flat dotted strings in one object per language. Flat means a missing
// key is a missing key - dataplane/../web has a test that compares the key sets,
// so a half-translated release fails CI instead of showing an English string in
// the middle of a Russian sentence.

import { reactive } from 'vue'

import en from './locales/en.js'
import vi from './locales/vi.js'
import ru from './locales/ru.js'
import zh from './locales/zh.js'

const messages = { en, vi, ru, zh }

// label is written in its own language on purpose: someone who has landed on a
// dashboard in a language they cannot read still has to find their way out.
export const LOCALES = [
  { code: 'en', label: 'English' },
  { code: 'vi', label: 'Tiếng Việt' },
  { code: 'ru', label: 'Русский' },
  { code: 'zh', label: '中文' },
]

// Intl tags for dates and numbers. Separate from the locale code because the two
// do not always match, and Intl wants a full tag.
const INTL_TAGS = { en: 'en-US', vi: 'vi-VN', ru: 'ru-RU', zh: 'zh-CN' }

const STORAGE_KEY = 'moswaf.locale'

// Object.hasOwn, not a truthy lookup: every value inherits "constructor",
// "toString" and friends from Object.prototype, so a truthy check accepts
// localStorage.setItem('moswaf.locale', 'constructor') as a real language. The
// consequences are mild - t() falls back to English and Intl ignores the tag -
// but an accepted value that is not a language should never be stored.
function known(table, key) {
  return typeof key === 'string' && Object.hasOwn(table, key)
}

function detect() {
  const saved = localStorage.getItem(STORAGE_KEY)
  if (known(messages, saved)) return saved

  // navigator.language is a full tag ("vi-VN", "zh-Hans-CN"); match the prefix.
  const prefix = String(navigator.language || 'en').toLowerCase().split('-')[0]
  return known(messages, prefix) ? prefix : 'en'
}

export const i18n = reactive({ locale: detect() })

export function setLocale(code) {
  if (!known(messages, code)) return
  i18n.locale = code
  localStorage.setItem(STORAGE_KEY, code)
  document.documentElement.lang = code
}

document.documentElement.lang = i18n.locale

/**
 * Translate a key. Reading i18n.locale is what makes every component using t()
 * re-render when the language changes, so no component needs a watcher.
 *
 *   t('sites.deleteConfirm', { name: 'shop' })
 *
 * An unknown key falls back to English and then to the key itself, which is ugly
 * on screen by design - a silent empty string would hide the mistake.
 */
export function t(key, vars) {
  const table = known(messages, i18n.locale) ? messages[i18n.locale] : messages.en
  let s = Object.hasOwn(table, key) ? table[key] : undefined
  if (s === undefined && Object.hasOwn(messages.en, key)) s = messages.en[key]
  if (s === undefined) return key
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, name) => (vars[name] !== undefined ? vars[name] : m))
  return s
}

export function intlTag() {
  return known(INTL_TAGS, i18n.locale) ? INTL_TAGS[i18n.locale] : 'en-US'
}
