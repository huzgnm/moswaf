// Shell state shared between the layout and the views.
//
// The sidebar's collapsed state is the operator's preference and survives a
// reload. The page scope (which window a view is looking at and when it last
// refreshed) is written by the view and shown in the topbar, so the frame can
// say "24 giờ · cập nhật 10:42" without every view drawing its own header.

import { reactive, watch } from 'vue'

const COLLAPSE_KEY = 'moswaf.sidebar'

export const ui = reactive({
  sidebarCollapsed: localStorage.getItem(COLLAPSE_KEY) === '1',
  sidebarOpen: false,          // the mobile drawer
  scope: '',                   // e.g. a translated range label
  updatedAt: null,             // Date of the last successful refresh, or null
})

watch(() => ui.sidebarCollapsed, (v) => localStorage.setItem(COLLAPSE_KEY, v ? '1' : '0'))

export function setScope(scope, updatedAt = null) {
  ui.scope = scope || ''
  ui.updatedAt = updatedAt
}

export function clearScope() {
  ui.scope = ''
  ui.updatedAt = null
}
