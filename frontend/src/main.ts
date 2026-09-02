import { createApp } from 'vue'
import { createPinia } from 'pinia'
import PrimeVue from 'primevue/config'
import { definePreset } from '@primeuix/themes'
import Aura from '@primeuix/themes/aura'

const AirlockPreset = definePreset(Aura, {
  semantic: {
    primary: {
      50: '{indigo.50}',
      100: '{indigo.100}',
      200: '{indigo.200}',
      300: '{indigo.300}',
      400: '{indigo.400}',
      500: '{indigo.500}',
      600: '{indigo.600}',
      700: '{indigo.700}',
      800: '{indigo.800}',
      900: '{indigo.900}',
      950: '{indigo.950}',
    },
  },
})
import ToastService from 'primevue/toastservice'
import ConfirmationService from 'primevue/confirmationservice'
import distribution from '@airlock/i18n-distribution'
import '@fontsource-variable/inter/wght.css'
import 'primeicons/primeicons.css'
import './style.css'

import App from './App.vue'
import api from './api/client'
import router from './router'
import { useAuthStore } from './stores/auth'
import { useTheme } from './composables/useTheme'
import { applyAuthStatusLocale, createAirlockI18n, type AuthLocaleStatus } from './i18n'

// Apply the persisted theme at boot. useTheme's module-level watchEffect
// toggles the `.dark` class (which PrimeVue's darkModeSelector keys on);
// it only runs once the composable is imported, so pull it in here rather
// than relying on a view to do it lazily.
useTheme()

const airlockI18n = createAirlockI18n(distribution, {
  document,
  preferredLocales: navigator.languages,
})
const app = createApp(App)
const pinia = createPinia()

app.use(pinia)
app.use(airlockI18n)
app.use(PrimeVue, {
  locale: airlockI18n.primeVueLocale.value,
  theme: {
    preset: AirlockPreset,
    options: {
      darkModeSelector: '.dark',
    },
  },
})
airlockI18n.bindPrimeVue(app.config.globalProperties.$primevue.config)
app.use(ToastService)
app.use(ConfirmationService)

const authStore = useAuthStore()

async function bootstrap() {
  let status: AuthLocaleStatus | undefined
  try {
    const response = await api.get('/auth/status')
    status = response.data
  } catch {
    // Auth initialization below retains the existing degraded-startup behavior.
  }

  // Before activation, the browser match remains a suggestion for the account
  // form. Once activated, the persisted system locale is authoritative.
  if (status) {
    try {
      applyAuthStatusLocale(airlockI18n, status)
    } catch (error) {
      console.error('Cannot apply the persisted Airlock UI locale', error)
      const warning = document.createElement('div')
      warning.setAttribute('role', 'alert')
      warning.style.cssText = 'padding:0.75rem 1rem;background:#7f1d1d;color:#fff;font:500 0.875rem/1.4 Inter,sans-serif'
      warning.textContent = distribution.locales[distribution.defaultLocale]
        .messages['common.locale.unsupportedBuild']
      document.body.prepend(warning)
    }
  }

  // Initialize auth before installing the router: route guards read the
  // authenticated user on their first navigation.
  await authStore.init()
  app.use(router)
  app.mount('#app')
}

void bootstrap()
