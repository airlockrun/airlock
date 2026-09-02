export interface MessageDescriptor {
  defaultMessage: string
  description: string
}

export function defineMessages<const Messages extends Record<string, MessageDescriptor>>(
  messages: Messages,
): Messages {
  return messages
}
