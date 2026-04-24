/**
 * WebSocket client for Airlock real-time events.
 *
 * Subscriptions are server-driven: the backend auto-subscribes this socket
 * to every agent the authenticated user is a member of on connect. The
 * client never sends subscribe/unsubscribe messages — any durable access
 * change goes through agent_members in the DB and takes effect on the next
 * WS reconnect.
 */

interface RawEnvelope {
  type: string
  requestId?: string
  topicId?: string
  payload?: unknown
}

type Handler = (payload: unknown) => void

export class AirlockWS {
  private socket: WebSocket | null = null
  private handlers = new Map<string, Set<Handler>>()
  private token: string | null = null
  private reconnectDelay = 1000
  private maxReconnectDelay = 30000
  private shouldReconnect = false

  connect(token: string) {
    this.token = token
    this.shouldReconnect = true
    this.doConnect()
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
    if (!this.token) return
    if (this.socket) {
      // Detach handlers BEFORE close() so the old socket's onclose doesn't
      // schedule another doConnect on top of this manual reconnect — that
      // race leaves two live sockets delivering every message twice.
      this.detach(this.socket)
      this.socket.close()
      this.socket = null
    }
    this.doConnect()
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

  private doConnect() {
    if (!this.token) return

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${window.location.host}/ws?token=${this.token}`
    this.socket = new WebSocket(url)

    this.socket.onopen = () => {
      this.reconnectDelay = 1000
      console.log('[ws] connected to', url.replace(/token=[^&]+/, 'token=***'))
      this.emit('_connected', null)
    }

    this.socket.onmessage = (event) => {
      try {
        const envelope: RawEnvelope = JSON.parse(event.data)
        this.emit(envelope.type, envelope.payload)
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
        setTimeout(() => this.doConnect(), this.reconnectDelay)
        this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxReconnectDelay)
      }
    }

    this.socket.onerror = (event) => {
      console.error('[ws] error', event)
      // onclose will fire after onerror — reconnect handled there.
    }
  }

  private emit(type: string, payload: unknown) {
    const handlers = this.handlers.get(type)
    if (handlers) {
      for (const handler of handlers) {
        handler(payload)
      }
    }
  }
}

/** Singleton WebSocket instance. */
export const ws = new AirlockWS()
