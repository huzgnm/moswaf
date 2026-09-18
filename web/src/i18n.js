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
// english is the secondary line, for the same reason in the other direction.
export const LOCALES = [
  { code: 'vi', label: 'Tiếng Việt',  english: 'Vietnamese' },
  { code: 'en', label: 'English',     english: 'English' },
  { code: 'ru', label: 'Русский',     english: 'Russian' },
  { code: 'zh', label: '中文',         english: 'Chinese' },
]

// The base language. It is what the dashboard opens in for a country with no
// language of its own here, and what t() falls back to for a key a translation
// is missing.
export const DEFAULT_LOCALE = 'en'

// Where the dashboard lands when nothing at all can be worked out about who is
// looking at it - an admin port reached through an SSH tunnel, a browser that
// reports no language. The operators of this product are Vietnamese, so that is
// the better guess than the base language.
export const FALLBACK_LOCALE = 'vi'

// Country -> interface language. Only countries where one of the four is
// genuinely the working language are listed; everywhere else opens in English,
// which is the safer guess than a language the reader may not have.
//
// The table lives here rather than in the control plane on purpose: which
// language a country should open in is a product decision that changes when a
// language is added, and the server's job is only to report which country it is.
//
// Singapore is English: four official languages, but English is the language of
// administration and of most working screens. Hong Kong and Macau get Chinese
// even though they read traditional characters and this ships simplified -
// closer than English for most readers there, and one click from right.
// Ukraine is deliberately absent: a Russian interface is not a neutral default.
const COUNTRY_LOCALE = {
  VN: 'vi',
  CN: 'zh', HK: 'zh', MO: 'zh',
  RU: 'ru', BY: 'ru', KZ: 'ru', KG: 'ru',
}

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

// The language the operator picked, if they ever picked one. Only an explicit
// choice is stored, so a guess never hardens into a setting nobody made.
function savedLocale() {
  const saved = localStorage.getItem(STORAGE_KEY)
  return known(messages, saved) ? saved : ''
}

export const i18n = reactive({ locale: savedLocale() || DEFAULT_LOCALE })

export function setLocale(code, remember = true) {
  if (!known(messages, code)) return
  i18n.locale = code
  if (remember) localStorage.setItem(STORAGE_KEY, code)
  document.documentElement.lang = code
}

document.documentElement.lang = i18n.locale

/**
 * Open the dashboard in the language of the country the operator is signing in
 * from. Called with the account the control plane just returned - `country` is
 * resolved there, against the same geolocation dataset the firewall decides
 * with, so an admin's address is never sent to a third party and a machine with
 * no route to the internet behaves the same as one with.
 *
 * Three cases:
 *
 *   - a country with a language here      -> that language
 *   - a country without one (say France)  -> DEFAULT_LOCALE, because knowing
 *                                            the reader is not in Vietnam is
 *                                            worth more than knowing nothing
 *   - no country                          -> FALLBACK_LOCALE
 *
 * **The last case is the ordinary one, not the exception.** The setup the README
 * recommends binds the panel to 127.0.0.1 and reaches it over an SSH tunnel, and
 * a loopback address has no country; neither does a private LAN one. This only
 * tells anyone anything on an installation whose panel is exposed directly.
 *
 * A language the operator picked themselves beats all of it - that is checked
 * first, and nothing here is written to storage, so a guess never hardens into a
 * setting they did not make.
 */
export function applyCountryLocale(account) {
  if (savedLocale()) return
  const country = String(account?.country || '').toUpperCase()
  if (!account?.country_resolved || !country) {
    setLocale(FALLBACK_LOCALE, false)
    return
  }
  // known(), not a plain lookup: `country` arrives from the network, and every
  // string inherits "constructor" and "toString" from Object.prototype, so a
  // truthy lookup would accept one of those as a country. The control plane
  // only emits two upper-case letters today - this is here so the dashboard
  // does not depend on it continuing to.
  setLocale(known(COUNTRY_LOCALE, country) ? COUNTRY_LOCALE[country] : DEFAULT_LOCALE, false)
}

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
