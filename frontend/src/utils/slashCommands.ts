import type { MessageId } from '@/i18n/messages'

export interface WebSlashCommand {
  name: string
  descriptionId: MessageId
}

// Web chat exposes the context commands from trigger.Registry. Bridge-only
// commands and /cancel (which has a dedicated in-chat button) stay out of the
// composer menu.
export const webSlashCommands: WebSlashCommand[] = [
  { name: 'clear', descriptionId: 'chat.slash.clearDescription' },
  { name: 'compact', descriptionId: 'chat.slash.compactDescription' },
]

export function matchingWebSlashCommands(input: string): WebSlashCommand[] {
  const match = input.match(/^\/([^\s]*)$/)
  if (!match) return []
  const query = match[1].toLowerCase()
  return webSlashCommands.filter(command => command.name.startsWith(query))
}
