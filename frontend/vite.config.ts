import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev rejimda /api va /reports so'rovlari backend (FastAPI :8000) ga uzatiladi —
// shu tufayli CORS muammosi bo'lmaydi va hisobot iframe'i ham ishlaydi.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/reports': 'http://127.0.0.1:8000',
    },
  },
})
