import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { mockApi } from './dev/mock-api.js'

// The build output goes straight into control/internal/web/dist so Go can embed it.
export default defineConfig({
  // mockApi() is a dev-server middleware for laying out the dashboard, and it
  // returns an inert plugin unless MOSWAF_MOCK=1 is set. `vite build` never runs
  // configureServer, so nothing in it can reach the bundle Go embeds. See
  // dev/mock-api.js for why sample data is needed at all.
  plugins: [vue(), mockApi()],
  build: {
    outDir: '../control/internal/web/dist',
    // Do not empty the directory: it holds a committed .gitignore so `go:embed`
    // always has a directory to embed, even in a fresh clone with no frontend build.
    // The `build` script clears the assets folder before running vite.
    emptyOutDir: false,
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5173,
    proxy: {
      // During `npm run dev`, proxy API calls to the control plane running locally.
      '/api': {
        // Override with MOSWAF_DEV_API when the control plane is not on 9443 -
        // another service on the machine may already hold that port.
        target: process.env.MOSWAF_DEV_API || 'https://127.0.0.1:9443',
        changeOrigin: true,
        secure: false, // self-signed certificate
      },
    },
  },
})
