import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// `define: { global: 'globalThis' }` polyfills the Node `global` reference that
// amazon-cognito-identity-js expects — without it the app crashes at import time
// with "global is not defined" in the browser.
export default defineConfig({
  plugins: [react()],
  define: {
    global: 'globalThis',
  },
  server: {
    port: 5173,
  },
})
