import type {
  PrimeVueLocaleAriaOptions,
  PrimeVueLocaleOptions,
} from 'primevue/config'

import type { MessageCatalog } from './messages'

export type TextDirection = 'ltr' | 'rtl'

export type PrimeVueLocale = {
  [Key in keyof Required<PrimeVueLocaleOptions>]: Key extends 'aria'
    ? Required<PrimeVueLocaleAriaOptions>
    : Exclude<PrimeVueLocaleOptions[Key], undefined>
}

export interface LocaleDistribution {
  direction: TextDirection
  messages: MessageCatalog
  primeVue: PrimeVueLocale
}

export interface I18nDistribution {
  defaultLocale: string
  locales: Readonly<Record<string, LocaleDistribution>>
}
