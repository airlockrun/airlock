import type { App, InjectionKey, Plugin, Ref } from 'vue'
import { inject, readonly, ref } from 'vue'
import type { PrimeVueConfiguration } from 'primevue/config'
import { defaultOptions } from 'primevue/config'
import { createI18n } from 'vue-i18n'

import type {
  I18nDistribution,
  LocaleDistribution,
  PrimeVueLocale,
} from './distribution'
import type { MessageCatalog, MessageId } from './messages'
import { messageDescriptors } from './messages'

export interface I18nEnvironment {
  document: Document
  preferredLocales: readonly string[]
}

export interface AirlockI18n extends Plugin {
  readonly locale: Readonly<Ref<string>>
  readonly availableLocales: readonly string[]
  readonly primeVueLocale: Readonly<Ref<PrimeVueLocale>>
  t(id: MessageId, values?: Record<string, string | number>): string
  setLocale(locale: string): void
  formatDate(value: Date | number, options?: Intl.DateTimeFormatOptions): string
  formatNumber(value: number | bigint, options?: Intl.NumberFormatOptions): string
  bindPrimeVue(config: PrimeVueConfiguration): void
}

export interface AirlockI18nComposable {
  readonly locale: Readonly<Ref<string>>
  readonly availableLocales: readonly string[]
  t(id: MessageId, values?: Record<string, string | number>): string
  setLocale(locale: string): void
  formatDate(value: Date | number, options?: Intl.DateTimeFormatOptions): string
  formatNumber(value: number | bigint, options?: Intl.NumberFormatOptions): string
}

export interface AuthLocaleStatus {
  activated?: boolean
  ui_locale?: unknown
}

const airlockI18nKey: InjectionKey<AirlockI18n> = Symbol('airlock-i18n')

export function createAirlockI18n(
  distribution: I18nDistribution,
  environment: I18nEnvironment,
): AirlockI18n {
  validateDistribution(distribution)

  const availableLocales = Object.freeze(Object.keys(distribution.locales))
  const initialLocale = resolveInitialLocale(distribution, environment)
  const locale = ref(initialLocale)
  const primeVueLocale = ref(distribution.locales[initialLocale].primeVue)
  let primeVueConfig: PrimeVueConfiguration | undefined

  const vueI18n = createI18n({
    legacy: false,
    locale: initialLocale,
    fallbackLocale: false,
    pluralRules: {
      ru: russianPluralIndex,
    },
    missing(missingLocale, id) {
      throw new Error(`Missing i18n message ${id} for locale ${missingLocale}`)
    },
    messages: Object.fromEntries(
      Object.entries(distribution.locales).map(([id, definition]) => [id, definition.messages]),
    ),
  })

  function applyLocale(id: string): void {
    const definition = distribution.locales[id]
    if (!definition) {
      throw new Error(`Unsupported locale: ${id}`)
    }

    locale.value = id
    vueI18n.global.locale.value = id
    primeVueLocale.value = definition.primeVue
    if (primeVueConfig) primeVueConfig.locale = definition.primeVue
    environment.document.documentElement.lang = id
    environment.document.documentElement.dir = definition.direction
  }

  let service: AirlockI18n
  service = {
    install(app: App): void {
      app.use(vueI18n)
      app.provide(airlockI18nKey, service)
    },
    locale: readonly(locale),
    availableLocales,
    primeVueLocale: readonly(primeVueLocale),
    t(id: MessageId, values: Record<string, string | number> = {}): string {
      return vueI18n.global.t(id, values)
    },
    setLocale(id: string): void {
      applyLocale(canonicalLocale(id, 'locale'))
    },
    formatDate(value: Date | number, options?: Intl.DateTimeFormatOptions): string {
      return new Intl.DateTimeFormat(locale.value, options).format(value)
    },
    formatNumber(value: number | bigint, options?: Intl.NumberFormatOptions): string {
      return new Intl.NumberFormat(locale.value, options).format(value)
    },
    bindPrimeVue(config: PrimeVueConfiguration): void {
      if (primeVueConfig) throw new Error('PrimeVue locale is already bound')
      primeVueConfig = config
      primeVueConfig.locale = primeVueLocale.value
    },
  }

  applyLocale(initialLocale)
  return service
}

function russianPluralIndex(choice: number, choicesLength: number): number {
  const value = Math.abs(choice)
  const mod10 = value % 10
  const mod100 = value % 100
  const one = mod10 === 1 && mod100 !== 11
  if (choicesLength === 2) return one ? 0 : 1
  if (one) return 0
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return 1
  return 2
}

export function useAirlockI18n(): AirlockI18nComposable {
  const service = inject(airlockI18nKey)
  if (!service) throw new Error('Airlock i18n is not installed')

  return {
    locale: service.locale,
    availableLocales: service.availableLocales,
    t: service.t,
    setLocale: service.setLocale,
    formatDate: service.formatDate,
    formatNumber: service.formatNumber,
  }
}

export function applyAuthStatusLocale(i18n: Pick<AirlockI18n, 'setLocale'>, status: AuthLocaleStatus): void {
  if (status.activated !== true) return
  if (typeof status.ui_locale !== 'string') {
    throw new Error('Activated server returned no valid UI locale')
  }
  i18n.setLocale(status.ui_locale)
}

export function validateDistribution(distribution: I18nDistribution): void {
  if (!distribution || typeof distribution !== 'object') {
    throw new Error('I18n distribution must be an object')
  }
  if (!distribution.locales || typeof distribution.locales !== 'object') {
    throw new Error('I18n distribution locales must be an object')
  }

  const localeEntries = Object.entries(distribution.locales)
  if (localeEntries.length === 0) throw new Error('I18n distribution has no locales')

  const expectedMessageIds = Object.keys(messageDescriptors)
  for (const [id, descriptor] of Object.entries(messageDescriptors)) {
    if (!descriptor.defaultMessage.trim()) throw new Error(`Message ${id} has no default message`)
    if (!descriptor.description.trim()) throw new Error(`Message ${id} has no translator description`)
  }

  for (const [id, definition] of localeEntries) {
    if (canonicalLocale(id, 'distribution locale') !== id) {
      throw new Error(`Distribution locale must use its canonical form: ${id}`)
    }
    validateLocaleDefinition(id, definition, expectedMessageIds)
  }

  const defaultLocale = canonicalLocale(distribution.defaultLocale, 'default locale')
  if (defaultLocale !== distribution.defaultLocale) {
    throw new Error(`Default locale must use its canonical form: ${distribution.defaultLocale}`)
  }
  if (!distribution.locales[defaultLocale]) {
    throw new Error(`Default locale is not distributed: ${defaultLocale}`)
  }
}

function validateLocaleDefinition(
  locale: string,
  definition: LocaleDistribution,
  expectedMessageIds: string[],
): void {
  if (!definition || typeof definition !== 'object') {
    throw new Error(`Locale ${locale} must be an object`)
  }
  if (definition.direction !== 'ltr' && definition.direction !== 'rtl') {
    throw new Error(`Locale ${locale} has an invalid text direction`)
  }
  if (!definition.messages || typeof definition.messages !== 'object') {
    throw new Error(`Locale ${locale} messages must be an object`)
  }

  const actualMessageIds = Object.keys(definition.messages)
  const missing = expectedMessageIds.filter((id) => !actualMessageIds.includes(id))
  const unknown = actualMessageIds.filter((id) => !expectedMessageIds.includes(id))
  if (missing.length > 0) throw new Error(`Locale ${locale} is missing messages: ${missing.join(', ')}`)
  if (unknown.length > 0) throw new Error(`Locale ${locale} has unknown messages: ${unknown.join(', ')}`)

  for (const [id, message] of Object.entries(definition.messages)) {
    if (typeof message !== 'string' || !message.trim()) {
      throw new Error(`Locale ${locale} has an empty message: ${id}`)
    }
  }

  if (!defaultOptions.locale) throw new Error('PrimeVue did not provide its required locale')
  validatePrimeVueLocale(locale, definition.primeVue, defaultOptions.locale, 'primeVue')
}

function validatePrimeVueLocale(
  locale: string,
  value: unknown,
  template: unknown,
  path: string,
): void {
  if (Array.isArray(template)) {
    if (!Array.isArray(value) || value.length !== template.length) {
      throw new Error(`Locale ${locale} has invalid PrimeVue data at ${path}`)
    }
    for (let index = 0; index < template.length; index += 1) {
      validatePrimeVueLocale(locale, value[index], template[index], `${path}[${index}]`)
    }
    return
  }

  if (template && typeof template === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new Error(`Locale ${locale} has invalid PrimeVue data at ${path}`)
    }
    const templateKeys = Object.keys(template)
    const valueKeys = Object.keys(value)
    const missing = templateKeys.filter((key) => !valueKeys.includes(key))
    const unknown = valueKeys.filter((key) => !templateKeys.includes(key))
    if (missing.length > 0 || unknown.length > 0) {
      throw new Error(`Locale ${locale} has incomplete PrimeVue data at ${path}`)
    }
    for (const key of templateKeys) {
      validatePrimeVueLocale(
        locale,
        (value as Record<string, unknown>)[key],
        (template as Record<string, unknown>)[key],
        `${path}.${key}`,
      )
    }
    return
  }

  if (typeof value !== typeof template || (typeof value === 'string' && !value.trim())) {
    throw new Error(`Locale ${locale} has invalid PrimeVue data at ${path}`)
  }
}

function resolveInitialLocale(
  distribution: I18nDistribution,
  environment: I18nEnvironment,
): string {
  for (const preferred of environment.preferredLocales) {
    const locale = canonicalLocale(preferred, 'preferred locale')
    if (distribution.locales[locale]) return locale
    const language = locale.split('-')[0]
    if (distribution.locales[language]) return language
  }
  return distribution.defaultLocale
}

function canonicalLocale(locale: string, source: string): string {
  try {
    const [canonical] = Intl.getCanonicalLocales(locale)
    if (!canonical) throw new Error('empty locale')
    return canonical
  } catch {
    throw new Error(`Invalid ${source}: ${locale}`)
  }
}

export type { I18nDistribution, MessageCatalog, MessageId }
