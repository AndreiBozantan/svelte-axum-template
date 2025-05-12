import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [svelte()],
  server: {
    port: 5173,
    proxy: {
      // Proxy API requests to the backend during development
      '/': {
        target: 'http://localhost:3000',
        changeOrigin: true,
        secure: false
      },
    }
  }
})
