import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// The build output goes straight into control/internal/web/dist so Go can embed it.
export default defineConfig({
  plugins: [vue()],
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
        target: 'https://127.0.0.1:9443',
        changeOrigin: true,
        secure: false, // self-signed certificate
      },
    },
  },
})
