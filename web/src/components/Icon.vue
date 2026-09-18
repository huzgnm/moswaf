<script setup>
// One stroke-icon set, drawn on a 24-unit grid at 1.7px so every icon in the
// dashboard has the same weight. Inline SVG rather than an icon package: the
// runtime dependency list is vue and vue-router, on purpose.
const PATHS = {
  overview:  'M3 13h4l3-8 4 16 3-8h4',
  sites:     'M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18',
  events:    'M4 5h16M4 12h10M4 19h7M17 15l2 2 4-4',
  rules:     'M9 4h10a1 1 0 011 1v14a1 1 0 01-1 1H9M5 8h8M5 12h8M5 16h5',
  ips:       'M4 6h16v5H4zM4 13h16v5H4zM7 8.5h.01M7 15.5h.01',
  ratelimit: 'M12 20a8 8 0 100-16 8 8 0 000 16zM12 8v4l2.5 2.5M4 12H2M22 12h-2',
  settings:  'M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z',
  signout:   'M10 17l5-5-5-5M15 12H3M9 4h9a2 2 0 012 2v12a2 2 0 01-2 2H9',
  menu:      'M4 7h16M4 12h16M4 17h16',
  collapse:  'M15 6l-6 6 6 6',
  expand:    'M9 6l6 6-6 6',
  shield:    'M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z',
  shieldOk:  'M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3zM9 12l2 2 4-4',
  shieldOff: 'M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3zM9.5 9.5l5 5M14.5 9.5l-5 5',
  alert:     'M12 9v4M12 17h.01M10.3 3.9L2.5 17.4A2 2 0 004.2 20.5h15.6a2 2 0 001.7-3.1L13.7 3.9a2 2 0 00-3.4 0z',
  check:     'M5 12l4.5 4.5L19 7',
  x:         'M6 6l12 12M18 6L6 18',
  chevronR:  'M9 6l6 6-6 6',
  arrowR:    'M5 12h14M13 6l6 6-6 6',
  external:  'M14 4h6v6M20 4l-9 9M19 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V6a1 1 0 011-1h5',
  refresh:   'M20 12a8 8 0 01-14.5 4.6M4 12a8 8 0 0114.5-4.6M4 4v5h5M20 20v-5h-5',
  search:    'M11 18a7 7 0 100-14 7 7 0 000 14zM20 20l-4-4',
  activity:  'M3 12h4l3-7 4 14 3-7h4',
  zap:       'M13 2L4 14h7l-1 8 9-12h-7l1-8z',
  ban:       'M12 21a9 9 0 100-18 9 9 0 000 18zM5.6 5.6l12.8 12.8',
  globe:     'M12 21a9 9 0 100-18 9 9 0 000 18zM3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18',
  clock:     'M12 21a9 9 0 100-18 9 9 0 000 18zM12 7v5l3 2',
  server:    'M4 5h16v5H4zM4 14h16v5H4zM7 7.5h.01M7 16.5h.01',
  db:        'M12 8c4.4 0 8-1.3 8-3s-3.6-3-8-3-8 1.3-8 3 3.6 3 8 3zM4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3',
  inbox:     'M22 12h-6l-2 3h-4l-2-3H2M5 5h14l3 7v7a2 2 0 01-2 2H4a2 2 0 01-2-2v-7l3-7z',
  plus:      'M12 5v14M5 12h14',
  lock:      'M6 11V8a6 6 0 0112 0v3M5 11h14v10H5z',
  key:       'M15 3a6 6 0 00-5.7 7.9L3 17.2V21h3.8l.9-.9v-2.1h2.1l1.4-1.4v-2.2h2.2l.4-.4A6 6 0 1015 3z',
  edit:      'M4 20h4l10.5-10.5a2 2 0 000-2.8l-1.2-1.2a2 2 0 00-2.8 0L4 16v4zM13 7l4 4',
  trash:     'M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3',
  users:     'M16 19v-2a4 4 0 00-4-4H7a4 4 0 00-4 4v2M9.5 10a3.5 3.5 0 100-7 3.5 3.5 0 000 7zM21 19v-2a4 4 0 00-3-3.9M15.5 3.1a3.5 3.5 0 010 6.8',
  info:      'M12 21a9 9 0 100-18 9 9 0 000 18zM12 11v5M12 8h.01',
  filter:    'M3 5h18l-7 8v6l-4 2v-8L3 5z',
  eye:       'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 15a3 3 0 100-6 3 3 0 000 6z',
  radar:     'M12 21a9 9 0 100-18 9 9 0 000 18zM12 17a5 5 0 100-10 5 5 0 000 10zM12 13a1 1 0 100-2 1 1 0 000 2zM12 12l6.4-6.4',
  trendUp:   'M4 17l6-6 4 4 6-6M14 9h6v6',
  trendDown: 'M4 7l6 6 4-4 6 6M14 15h6V9',
  minus:     'M5 12h14',
}

defineProps({ name: { type: String, required: true } })
</script>

<template>
  <svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"
       stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    <path :d="PATHS[name] || PATHS.info" />
  </svg>
</template>
