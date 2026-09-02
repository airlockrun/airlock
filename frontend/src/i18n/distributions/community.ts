import type { I18nDistribution } from '../distribution'
import { defaultMessages } from '../messages'
import { primeVueEnglish } from '../primevue-en'

export const communityDistribution = {
  defaultLocale: 'en',
  locales: {
    en: {
      direction: 'ltr',
      messages: defaultMessages,
      primeVue: primeVueEnglish,
    },
  },
} satisfies I18nDistribution

export default communityDistribution
