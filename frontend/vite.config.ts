import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 前后端分离：dev 下将 /api 代理到 FastAPI 后端
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
