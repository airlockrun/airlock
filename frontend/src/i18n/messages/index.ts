import { administrationMessages } from './administration'
import { agentConfigMessages } from './agentConfig'
import { agentMessages } from './agents'
import { authMessages } from './auth'
import { chatMessages } from './chat'
import { commonMessages } from './common'
import { connectorMessages } from './connectors'
import { operationMessages } from './operations'
import { resourceMessages } from './resources'

export type { MessageDescriptor } from './define'

export const messageDescriptors = {
  ...commonMessages,
  ...authMessages,
  ...agentMessages,
  ...agentConfigMessages,
  ...chatMessages,
  ...operationMessages,
  ...resourceMessages,
  ...connectorMessages,
  ...administrationMessages,
} as const

export type MessageId = keyof typeof messageDescriptors

export type MessageCatalog = Readonly<Record<MessageId, string>>

export const defaultMessages = Object.fromEntries(
  Object.entries(messageDescriptors).map(([id, descriptor]) => [id, descriptor.defaultMessage]),
) as MessageCatalog
