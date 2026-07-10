import { defineConfig } from 'vite';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';
import { svelte } from '@sveltejs/vite-plugin-svelte';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf-8'));
const version = pkg.version;

// https://vitejs.dev/config/
export default defineConfig({
    base: '/',
    define: {
        __APP_VERSION__: JSON.stringify(version),
    },
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
            '/docs': {
                target: 'http://localhost:3000',
                changeOrigin: true,
            },
            '/openapi.json': {
                target: 'http://localhost:3000',
                changeOrigin: true,
            },
        },
    },
    test: {
        environment: 'jsdom',
    },
});
