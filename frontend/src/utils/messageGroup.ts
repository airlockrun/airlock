/**
 * Fold a turn's persisted rows into one assistant bubble, preserving the
 * true text↔tool emission order.
 *
 * The backend persists each LLM step as its own `agent_messages` row
 * (assistant for the step's text + tool-call parts, a separate role=tool
 * row for each result). Each assistant row's `parts` is an *ordered*
 * goai Content array, and a multi-step run_js loop is one row per step in
 * `seq` order. This helper walks parts in order and emits an ordered
 * `blocks[]` (text / tool, interleaved exactly as the model produced
 * them), folding every row that shares a `runId` into the first one and
 * marking the rest `_hidden`. Tool-result rows patch their matching tool
 * block's `output` and are hidden too. The renderer just iterates
 * `blocks` — no "tools first, text last" reordering.
 *
 * Mutates `msgs` in place (sets `blocks`, `toolName`, `_hidden`,
 * `displayParts`) and returns it for fluent use.
 */

import type { AgentMessageInfo } from '@/gen/airlock/v1/types_pb'

// Outcome is the structured, persisted tool status derived from the
// discriminated tool-result output (no text heuristics). '' = unknown
// (e.g. a still-running live call before its result arrives).
export type ToolOutcome = '' | 'success' | 'error' | 'denied'

export interface ToolBlock {
  kind: 'tool'
  toolCallId: string
  toolName: string // raw name — drives collapse defaults + promptAgentText
  label: string // human display name (toolLabel of name + args)
  input: string
  output: string
  error: string
  outcome: ToolOutcome
}

// toolOutputInfo resolves a discriminated ToolResultOutput (the persisted
// `output` object) to its display text + structured outcome.
export function toolOutputInfo(out: any): { text: string; outcome: ToolOutcome } {
  if (!out || typeof out !== 'object') return { text: '', outcome: 'success' }
  switch (out.type) {
    case 'execution-denied':
      return { text: out.reason || 'Tool call execution denied.', outcome: 'denied' }
    case 'error-text':
      return { text: String(out.value ?? ''), outcome: 'error' }
    case 'error-json':
      return { text: JSON.stringify(out.value), outcome: 'error' }
    case 'text':
      return { text: String(out.value ?? ''), outcome: 'success' }
    case 'json':
      return { text: JSON.stringify(out.value), outcome: 'success' }
    case 'content': {
      const items = Array.isArray(out.value) ? out.value : []
      const text = items
        .filter((i: any) => i && i.type === 'text')
        .map((i: any) => i.text)
        .join('')
      return { text, outcome: 'success' }
    }
    default:
      return { text: '', outcome: 'success' }
  }
}

// toolLabel maps a raw tool name (+ its call args) to the human label
// shown in the transcript. Only the two framework tools are renamed;
// user-registered tools keep their own name. `args` may be the raw args
// object or a JSON string (live path); a slug is only pulled for
// promptAgent.
export function toolLabel(toolName: string, args?: unknown): string {
  if (toolName === 'run_js') return 'Code Run'
  if (toolName === 'promptAgent') {
    let a = args
    if (typeof a === 'string') {
      try { a = JSON.parse(a) } catch { a = undefined }
    }
    const slug = a && typeof a === 'object' ? (a as any).agent : undefined
    return slug ? `A2A Call (${slug})` : 'A2A Call'
  }
  return toolName
}

export interface TextBlock {
  kind: 'text'
  text: string
}

// MsgBlock is the single ordered render unit shared by the persisted
// path (enrichMessages) and the live streaming path (chat.ts), so both
// render an assistant turn identically and in true sequence order.
export type MsgBlock = TextBlock | ToolBlock

const metaKeys = new Set(['request_confirmation'])

/** Stringify tool args for display, dropping framework-only keys. */
// promptAgentText pulls the human-facing `text` out of a promptAgent
// tool result. The wire/LLM form is the full A2A envelope
// {text,taskId,contextId,state,artifacts} — the model needs the ids for
// thread continuity, but the human should only ever see `text`. Returns
// null for non-promptAgent tools or unparseable output so callers fall
// back to the raw `<pre>` render.
export function promptAgentText(toolName: string, output: string): string | null {
  if (toolName !== 'promptAgent' || !output) return null
  try {
    const o = JSON.parse(output)
    if (o && typeof o.text === 'string') return o.text
  } catch {
    /* not the envelope (e.g. an "Error: ..." string) — show as-is */
  }
  return null
}

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
  // source="llm": model-only context (e.g. the attached-files manifest)
  // persisted into the conversation but never meant for the human. Hide
  // it everywhere a transcript renders — same _hidden affordance folded
  // rows use.
  for (const msg of msgs) {
    if (msg.source === 'llm') (msg as any)._hidden = true
  }

  // Pass 1: walk each assistant row's ordered parts into an ordered
  // blocks[] (text / tool, interleaved as emitted). callEntries keeps a
  // reference to each tool block so pass 2 can fill its output when the
  // separate role=tool row is seen. Multi-step run_js loops persist one
  // assistant row per LLM step in seq order — fold every row sharing a
  // runId into the first, appending its blocks so the true cross-step
  // order (text → tool → text → tool …) is preserved.
  const callEntries = new Map<string, ToolBlock>()
  const runAnchor = new Map<string, AgentMessageInfo>()
  for (const msg of msgs) {
    if (msg.role !== 'assistant') continue
    const parts = parseParts((msg as any).parts)
    const rowBlocks: MsgBlock[] = []
    if (parts) {
      for (const p of parts) {
        if (p.type === 'tool-call' && p.toolCallId) {
          const tb: ToolBlock = {
            kind: 'tool',
            toolCallId: p.toolCallId,
            toolName: p.toolName || 'tool',
            label: toolLabel(p.toolName || 'tool', p.args),
            input: formatToolArgs(p.args),
            output: '',
            error: '',
            outcome: '',
          }
          callEntries.set(p.toolCallId, tb)
          rowBlocks.push(tb)
        } else if (p.type === 'text' && typeof p.text === 'string' && p.text) {
          const last = rowBlocks[rowBlocks.length - 1]
          // Coalesce consecutive text parts within a row (continuous
          // stream); a fold boundary across steps stays a separate block.
          if (last && last.kind === 'text') last.text += p.text
          else rowBlocks.push({ kind: 'text', text: p.text })
        }
      }
    }
    // No multipart parts (plain text answer): the whole content is the
    // single text block — only needed when this row folds into / anchors
    // a runId group; a lone plain-text row keeps the content fast-path.
    const runId = (msg as any).runId as string | undefined
    if (rowBlocks.length === 0 && msg.content && runId) {
      rowBlocks.push({ kind: 'text', text: msg.content })
    }

    if (runId) {
      const anchor = runAnchor.get(runId)
      if (anchor) {
        const anchorBlocks = ((anchor as any).blocks ??= [] as MsgBlock[])
        anchorBlocks.push(...rowBlocks)
        if (msg.content) {
          anchor.content = anchor.content ? `${anchor.content}\n${msg.content}` : msg.content
        }
        ;(msg as any)._hidden = true
        continue
      }
      runAnchor.set(runId, msg)
    }

    // Set blocks for the ordering-sensitive cases: any turn with a tool,
    // or a runId anchor (so later steps have somewhere to append). A lone
    // plain-text assistant row gets no blocks and uses the content path
    // unchanged.
    if (rowBlocks.some((b) => b.kind === 'tool') || runId) {
      ;(msg as any).blocks = rowBlocks
    }
  }

  // Pass 2: patch each tool-result row's output into its tool block (same
  // toolCallId) and hide the row. Persisted tool rows carry no structured
  // error field — live finalizeMessage prefixes errors with "Error: " in
  // content, and that's what's stored, so output carries it.
  for (const msg of msgs) {
    if (msg.role !== 'tool') continue
    const parts = parseParts((msg as any).parts)
    let toolCallId = ''
    let toolName = ''
    let resultOut: any
    if (parts) {
      for (const p of parts) {
        if ((p.type === 'tool-result' || p.type === 'tool') && p.toolCallId) {
          toolCallId = p.toolCallId
          toolName = p.toolName || ''
          resultOut = p.output
          break
        }
      }
    }
    if (!toolCallId) continue
    const entry = callEntries.get(toolCallId)
    if (entry) {
      // The discriminated `output` is authoritative for both display text
      // and the structured outcome (no text sniffing). Fall back to the
      // row content only when a part carries no output object.
      if (resultOut && typeof resultOut === 'object') {
        const info = toolOutputInfo(resultOut)
        entry.outcome = info.outcome
        if (info.outcome === 'error') entry.error = info.text
        else entry.output = info.text
      } else if (msg.content) {
        entry.output = msg.content
      }
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
