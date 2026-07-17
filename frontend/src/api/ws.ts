/**
 * WebSocket client for Airlock real-time events.
 *
 * Subscriptions are server-driven: the backend auto-subscribes this socket
 * to every agent the authenticated user is a member of on connect. The
 * client never sends subscribe/unsubscribe messages — any durable access
 * change goes through agent_grants in the DB; the server closes the socket so
 * this client reconnects with the current subscription set.
 */

import { isAuthRejection, refreshAccessToken } from '@/api/client'

export interface SubagentInfo {
  agentId: string
  runId: string
  slug?: string
}

export interface RawEnvelope {
  type: string
  requestId?: string
  topicId?: string
  // userId / conversationId are set by the backend for run events so
  // the frontend can route by chat card and so server-side user-id
  // gating is observable here (the server already filtered; this is
  // for client-side card routing).
  userId?: string
  // Hub-global monotonic publish sequence. We keep the max seen and
  // present it as ?since= on reconnect so the server replays only the
  // delta (or sends `resync`) instead of the whole per-topic buffer.
  seq?: number
  conversationId?: string
  // subagent tags the envelope as a sub-run event mirrored from an
  // A2A child run; chat store routes these into the parent's active
  // tool-call card instead of the main message stream.
  subagent?: SubagentInfo
  payload?: unknown
}

type Handler = (payload: unknown, envelope?: RawEnvelope) => void

export class AirlockWS {
  private socket: WebSocket | null = null
  private handlers = new Map<string, Set<Handler>>()
  private reconnectDelay = 1000
  private maxReconnectDelay = 30000
  private shouldReconnect = false
  // Max Envelope.seq processed; sent as ?since= on (re)connect for
  // delta replay. Resets to 0 on full page reload (new instance) — a
  // fresh load DB-loads anyway, so no replay is correct there.
  private lastSeq = 0
  // Per-build topics the client has dynamically subscribed to (Build page
  // open). Re-sent on every (re)connect so a drop mid-build resubscribes.
  private buildSubs = new Set<string>()

  /** Open the socket using the same-origin HttpOnly access cookie. */
  connect() {
    this.shouldReconnect = true
    void this.doConnect(false)
  }

  disconnect() {
    this.shouldReconnect = false
    if (this.socket) {
      this.detach(this.socket)
      this.socket.close()
      this.socket = null
    }
  }

  /**
   * Force a reconnect so the server re-reads agent_members and includes any
   * newly-created or newly-shared agents in the auto-subscription set.
   * Called after actions that mutate membership (e.g., creating an agent).
   */
  reconnect() {
    if (!this.shouldReconnect) return
    if (this.socket) {
      // Detach handlers BEFORE close() so the old socket's onclose doesn't
      // schedule another doConnect on top of this manual reconnect — that
      // race leaves two live sockets delivering every message twice.
      this.detach(this.socket)
      this.socket.close()
      this.socket = null
    }
    void this.doConnect(false)
  }

  private detach(sock: WebSocket) {
    sock.onopen = null
    sock.onmessage = null
    sock.onclose = null
    sock.onerror = null
  }

  /** Register a handler for an event type. Returns an unsubscribe function. */
  onMessage(type: string, handler: Handler): () => void {
    if (!this.handlers.has(type)) {
      this.handlers.set(type, new Set())
    }
    this.handlers.get(type)!.add(handler)
    return () => {
      this.handlers.get(type)?.delete(handler)
    }
  }

  get connected(): boolean {
    return this.socket?.readyState === WebSocket.OPEN
  }

  /** Send a client→server control message. No-ops if the socket isn't open. */
  private send(type: string, payload: unknown) {
    if (this.socket?.readyState === WebSocket.OPEN) {
      this.socket.send(JSON.stringify({ type, payload }))
    }
  }

  /**
   * Subscribe to a build's verbose topic (codegen log + todos).
   * The Build page calls this on mount; the subscription is remembered and
   * re-sent on reconnect. The server gates it on build-view access.
   */
  subscribeBuild(buildId: string) {
    this.buildSubs.add(buildId)
    this.send('subscribe.build', { buildId })
  }

  /** Drop a per-build subscription (Build page unmount). */
  unsubscribeBuild(buildId: string) {
    this.buildSubs.delete(buildId)
    this.send('unsubscribe.build', { buildId })
  }

  private async doConnect(refreshFirst: boolean) {
    if (refreshFirst) {
      try {
        await refreshAccessToken()
      } catch (err) {
        // Only treat a 401/403 from the server as "refresh token is
        // dead." A transport error or 5xx (Caddy 502/503 while airlock
        // is restarting) is transient — keep the reconnect loop alive
        // with backoff so the WS comes back as soon as the server does,
        // and keep credentials so a subsequent REST call works too.
        if (isAuthRejection(err)) {
          this.shouldReconnect = false
          return
        }
        // Transient: fall through into the reconnect-with-backoff path
        // below by faking an onclose-style retry.
        if (this.shouldReconnect) {
          setTimeout(() => void this.doConnect(true), this.reconnectDelay)
          this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay)
        }
        return
      }
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const since = this.lastSeq > 0 ? `?since=${this.lastSeq}` : ''
    const url = `${protocol}//${window.location.host}/ws${since}`
    this.socket = new WebSocket(url)

    this.socket.onopen = () => {
      this.reconnectDelay = 1000
      console.log('[ws] connected')
      // Re-arm any dynamic per-build subscriptions across a reconnect.
      for (const id of this.buildSubs) this.send('subscribe.build', { buildId: id })
      this.emit('_connected', null)
    }

    this.socket.onmessage = (event) => {
      try {
        const envelope: RawEnvelope = JSON.parse(event.data)
        if (typeof envelope.seq === 'number' && envelope.seq > this.lastSeq) {
          this.lastSeq = envelope.seq
        }
        this.emit(envelope.type, envelope.payload, envelope)
      } catch {
        // Ignore malformed messages.
      }
    }

    this.socket.onclose = (event) => {
      console.warn('[ws] disconnected', { code: event.code, reason: event.reason, wasClean: event.wasClean })
      this.socket = null
      this.emit('_disconnected', null)
      if (this.shouldReconnect) {
        console.log('[ws] reconnecting in', this.reconnectDelay, 'ms')
        setTimeout(() => void this.doConnect(true), this.reconnectDelay)
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay)
      }
    }

    this.socket.onerror = (event) => {
      console.error('[ws] error', event)
      // onclose will fire after onerror — reconnect handled there.
    }
  }

  private emit(type: string, payload: unknown, envelope?: RawEnvelope) {
    const handlers = this.handlers.get(type)
    if (handlers) {
      for (const handler of handlers) {
        handler(payload, envelope)
      }
    }
  }

}

/** Singleton WebSocket instance. */
export const ws = new AirlockWS()
