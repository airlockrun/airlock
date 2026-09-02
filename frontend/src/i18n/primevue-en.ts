import { defaultOptions } from 'primevue/config'

import type { PrimeVueLocale } from './distribution'

if (!defaultOptions.locale) {
  throw new Error('PrimeVue did not provide its required English locale')
}

export const primeVueEnglish = defaultOptions.locale as PrimeVueLocale
