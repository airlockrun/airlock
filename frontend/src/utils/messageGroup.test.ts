import { describe, expect, it } from 'vitest'

import type { AgentMessageInfo } from '@/gen/airlock/v1/types_pb'
import { enrichMessages } from './messageGroup'

describe('enrichMessages', () => {
  it.each(['llm', 'compaction'])('hides source=%s transcript rows', (source) => {
    const messages = [{
      $typeName: 'airlock.v1.AgentMessageInfo',
      id: `message-${source}`,
      role: 'assistant',
      source,
      content: 'internal context',
      costEstimate: 0,
    }] as AgentMessageInfo[]

    enrichMessages(messages)

    expect((messages[0] as any)._hidden).toBe(true)
  })
})
