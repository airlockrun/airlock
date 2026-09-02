import type { AirlockI18nComposable } from '@/i18n'
import { operationMessages } from '@/i18n/messages/operations'

type Translate = AirlockI18nComposable['t']
type FormatNumber = AirlockI18nComposable['formatNumber']

// buildBadgeText renders the "build in progress" badge label. During codegen
// it shows the agent's task progress (N/M); once the pipeline moves past
// codegen the phase drives a stage label so the badge doesn't freeze on the
// final task count while the image builds / migrations run / the container
// swaps. Phases come from AgentBuildEvent.phase.
export function buildBadgeText(
  phase: string,
  done: number,
  total: number,
  t?: Translate,
  formatNumber?: FormatNumber,
): string {
  const translate = t ?? defaultOperationMessage
  switch (phase) {
    case 'image': return translate('operations.build.phase.image')
    case 'connectors': return translate('operations.build.phase.connectors')
    case 'migrations': return translate('operations.build.phase.migrations')
    case 'deploy': return translate('operations.build.phase.deploy')
    default: return total > 0
      ? translate('operations.build.phase.buildingTasks', {
          doneFormatted: formatBuildNumber(done, formatNumber),
          countFormatted: formatBuildNumber(total, formatNumber),
          count: total,
        })
      : translate('operations.build.phase.building')
  }
}

function formatBuildNumber(value: number, formatNumber?: FormatNumber): string {
  if (formatNumber) return formatNumber(value)
  // The i18n service keeps <html lang> synchronized with the active locale.
  const locale = typeof document === 'undefined' ? undefined : document.documentElement.lang || undefined
  return new Intl.NumberFormat(locale).format(value)
}

function defaultOperationMessage(
  id: keyof typeof operationMessages,
  values: Record<string, string | number> = {},
): string {
  const choices = operationMessages[id].defaultMessage.split(' | ')
  const count = typeof values.count === 'number' ? values.count : 2
  const message = choices[count === 1 ? 0 : choices.length - 1]
  return message.replace(/\{(\w+)\}/g, (_, key: string) => String(values[key]))
}
