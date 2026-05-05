/**
 * Group tool messages into their parent assistant turn.
 *
 * The backend persists each `(tool-call, tool-result)` round as its own
 * `agent_messages` row (assistant for the call, role=tool for the result).
 * When we render those rows independently the visual layout fragments into
 * one bubble per row. This helper folds tool result rows into the
 * preceding assistant message's `toolCalls[]` array and marks the tool
 * row `_hidden` so the renderer skips it. The result is one cohesive
 * assistant bubble per turn that mirrors the streaming layout.
 *
 * Mutates `msgs` in place (sets `toolCalls`, `toolName`, `toolInput`,
 * `_hidden`, and `displayParts`) and returns it for fluent use.
 */

import type { AgentMessageInfo } from '@/gen/airlock/v1/types_pb'

export interface GroupedToolCall {
  toolCallId: string
  toolName: string
  input: string
  output: string
  error: string
}

const metaKeys = new Set(['request_confirmation'])

/** Stringify tool args for display, dropping framework-only keys. */
export function formatToolArgs(args: any): string {
  if (typeof args === 'string') return args
  if (args && typeof args === 'object') {
    const keys = Object.keys(args).filter((k) => !metaKeys.has(k))
    if (keys.length === 1) return String(args[keys[0]])
    const filtered: Record<string, any> = {}
    for (const k of keys) filtered[k] = args[k]
    return Object.entries(filtered)
      .map(([k, v]) => `${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`)
      .join('\n')
  }
  return ''
}

function parseParts(parts: unknown): any[] | null {
  if (!parts) return null
  try {
    const parsed = typeof parts === 'string' ? JSON.parse(parts) : parts
    return Array.isArray(parsed) ? parsed : null
  } catch {
    return null
  }
}

export function enrichMessages(msgs: AgentMessageInfo[]): AgentMessageInfo[] {
  // Pass 1: build toolCalls[] on every assistant message that called tools.
  // Keep references so pass 2 can mutate the same entries when the tool
  // result row arrives later in the stream.
  const callEntries = new Map<string, GroupedToolCall>()
  for (const msg of msgs) {
    if (msg.role !== 'assistant') continue
    const parts = parseParts((msg as any).parts)
    if (!parts) continue
    const calls: GroupedToolCall[] = []
    for (const p of parts) {
      if (p.type === 'tool-call' && p.toolCallId) {
        const entry: GroupedToolCall = {
          toolCallId: p.toolCallId,
          toolName: p.toolName || 'tool',
          input: formatToolArgs(p.args),
          output: '',
          error: '',
        }
        callEntries.set(p.toolCallId, entry)
        calls.push(entry)
      }
    }
    if (calls.length > 0) (msg as any).toolCalls = calls
  }

  // Pass 2: fold each tool result row into its parent assistant's entry.
  // Persisted tool messages don't carry a structured error field — the
  // live finalizeMessage code prefixes errors with "Error: " in content,
  // and that's what's stored. So we just propagate `content` as `output`
  // and leave error empty for persisted rows. Rows that have a parent
  // entry get marked _hidden so they don't render as their own bubble.
  for (const msg of msgs) {
    if (msg.role !== 'tool') continue
    const parts = parseParts((msg as any).parts)
    let toolCallId = ''
    let toolName = ''
    if (parts) {
      for (const p of parts) {
        if ((p.type === 'tool-result' || p.type === 'tool') && p.toolCallId) {
          toolCallId = p.toolCallId
          toolName = p.toolName || ''
          break
        }
      }
    }
    if (!toolCallId) continue
    const entry = callEntries.get(toolCallId)
    if (entry) {
      if (msg.content) entry.output = msg.content
      ;(msg as any)._hidden = true
    } else {
      // No parent assistant — render as a standalone tool bubble (legacy
      // path). Annotate so the renderer has the tool name to show.
      ;(msg as any).toolName = toolName || 'tool'
    }
  }

  // displayParts for notification / upload messages so the rich renderer
  // can use them. Same enrichment chat.ts used to do inline.
  for (const msg of msgs) {
    if (msg.source !== 'notification' && msg.source !== 'upload') continue
    const parts = parseParts((msg as any).parts)
    if (parts) (msg as any).displayParts = parts
  }

  return msgs
}
