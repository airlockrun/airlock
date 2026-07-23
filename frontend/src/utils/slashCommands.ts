export interface WebSlashCommand {
  name: string
  description: string
}

// Web chat exposes the context commands from trigger.Registry. Bridge-only
// commands and /cancel (which has a dedicated in-chat button) stay out of the
// composer menu.
export const webSlashCommands: WebSlashCommand[] = [
  { name: 'clear', description: 'Clear conversation context' },
  { name: 'compact', description: 'Summarize and compact context' },
]

export function matchingWebSlashCommands(input: string): WebSlashCommand[] {
  const match = input.match(/^\/([^\s]*)$/)
  if (!match) return []
  const query = match[1].toLowerCase()
  return webSlashCommands.filter(command => command.name.startsWith(query))
}
