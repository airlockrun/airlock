import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import Components from 'unplugin-vue-components/vite'
import { PrimeVueResolver } from '@primevue/auto-import-resolver'
import { fileURLToPath } from 'node:url'
import { resolve } from 'node:path'

const frontendRoot = fileURLToPath(new URL('.', import.meta.url))
const i18nDistribution = process.env.AIRLOCK_I18N_DISTRIBUTION
  ? resolve(frontendRoot, process.env.AIRLOCK_I18N_DISTRIBUTION)
  : fileURLToPath(new URL('./src/i18n/distributions/community.ts', import.meta.url))

export default defineConfig({
  plugins: [
    vue(),
    Components({
      resolvers: [PrimeVueResolver()],
    }),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      '@airlock/i18n-distribution': i18nDistribution,
    },
  },
  server: {
    // Dev-only: Vite's host-header check defends against DNS rebinding on
    // publicly-exposed dev servers, not relevant here (dev is behind Caddy on
    // loopback). Allowing any host lets users pick their own dev domain
    // without patching this file.
    allowedHosts: true,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/auth': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        bypass(req) {
          // /auth/relay is the frontend SPA route; everything else under
          // /auth (including /auth/relay-code, /auth/login, etc.) must
          // proxy to the backend. Match the exact path so a string
          // prefix doesn't swallow sibling endpoints.
          const path = req.url?.split('?')[0]
          if (path === '/auth/relay') return req.url
        },
      },
      '/ws': {
        target: 'http://localhost:8080',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
