import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'url';

// https://vitejs.dev/config/
export default defineConfig({
    base: '/',
    plugins: [svelte()],
    resolve: {
        alias: {
            $lib: fileURLToPath(new URL('./src/lib', import.meta.url)),
        },
    },
    build: {
        assetsDir: 'static',
    },
    server: {
        port: 5173,
        host: true,
        strictPort: true,
        // proxy API requests to the backend during development
        proxy: {
            '/api': {
                target: 'http://localhost:3000',
                changeOrigin: true,
            },
            '/user_info.js': {
                target: 'http://localhost:3000',
                changeOrigin: true,
            },
        },
    },
});
