import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Ban build duoc ghi thang vao control/internal/web/dist de Go nhung vao binary.
export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: '../control/internal/web/dist',
    // Khong xoa sach thu muc: trong do co .gitignore duoc commit de `go:embed`
    // luon co thu muc de nhung, ke ca khi vua clone va chua build frontend.
    // Script `build` da tu don thu muc assets truoc khi chay vite.
    emptyOutDir: false,
    chunkSizeWarningLimit: 900,
  },
  server: {
    port: 5173,
    proxy: {
      // Khi chay `npm run dev`, goi API sang control plane dang chay local.
      '/api': {
        target: 'https://127.0.0.1:9443',
        changeOrigin: true,
        secure: false, // chung chi tu ky
      },
    },
  },
})
