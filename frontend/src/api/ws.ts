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
  private reconnectDelay = 1000
  private maxReconnectDelay = 30000
  private shouldReconnect = false
  // Single in-flight refresh promise so concurrent reconnect attempts and
  // axios interceptor refreshes don't both POST /auth/refresh. The axios
  // interceptor manages its own promise; we don't share it (keeps ws.ts
  // self-contained), but the refresh endpoint itself is idempotent enough
  // that two concurrent calls just produce two access tokens — last write
  // to localStorage wins, both work until expiry.
  private refreshPromise: Promise<void> | null = null

  /**
   * Open the socket. Token argument is ignored — the connection always reads
   * the current access token from localStorage at handshake time so a token
   * refreshed by the REST interceptor (or by ws's own pre-connect refresh)
   * is picked up automatically. The argument stays in the signature so
   * existing call sites keep compiling.
   */
  connect(_token?: string) {
    this.shouldReconnect = true
    void this.doConnect()
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
    if (!localStorage.getItem('access_token')) return
    if (this.socket) {
      // Detach handlers BEFORE close() so the old socket's onclose doesn't
      // schedule another doConnect on top of this manual reconnect — that
      // race leaves two live sockets delivering every message twice.
      this.detach(this.socket)
      this.socket.close()
      this.socket = null
    }
    void this.doConnect()
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

  private async doConnect() {
    // Read fresh — REST interceptor or our own pre-connect refresh may have
    // rotated this since the last connect.
    let token = localStorage.getItem('access_token')
    if (!token) return

    // Server validates the token at handshake time only. If the cached
    // token is expired (typical after a long background tab + network
    // blip), the WS handshake 401s and we'd loop forever with the same
    // dead token. Refresh first when it's within 30s of expiry.
    if (this.tokenExpiringSoon(token)) {
      try {
        await this.ensureFreshToken()
        token = localStorage.getItem('access_token')
        if (!token) return
      } catch {
        // Refresh failed — refresh token is also dead. Stop the reconnect
        // loop, clear creds, and let the next user action trigger /login
        // through the REST interceptor.
        this.shouldReconnect = false
        localStorage.removeItem('access_token')
        localStorage.removeItem('refresh_token')
        return
      }
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = `${protocol}//${window.location.host}/ws?token=${token}`
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
        setTimeout(() => void this.doConnect(), this.reconnectDelay)
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

  /**
   * Returns true if the JWT's `exp` claim is within 30s of now (or the
   * token is unparseable, in which case treat as expired so we attempt a
   * refresh rather than handshaking with garbage).
   */
  private tokenExpiringSoon(token: string): boolean {
    try {
      const [, payload] = token.split('.')
      if (!payload) return true
      // base64url → base64
      const b64 = payload.replace(/-/g, '+').replace(/_/g, '/')
      const json = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '='))
      const claims = JSON.parse(json) as { exp?: number }
      if (typeof claims.exp !== 'number') return true
      return claims.exp * 1000 - Date.now() < 30_000
    } catch {
      return true
    }
  }

  /**
   * POST /auth/refresh and overwrite localStorage.access_token. Coalesces
   * concurrent calls onto a single in-flight promise so two reconnect
   * attempts (or a reconnect racing the REST interceptor) don't double-fire.
   * Throws if the refresh token is missing or the server rejects it.
   */
  private ensureFreshToken(): Promise<void> {
    if (this.refreshPromise) return this.refreshPromise
    const refreshToken = localStorage.getItem('refresh_token')
    if (!refreshToken) return Promise.reject(new Error('no refresh token'))
    this.refreshPromise = fetch('/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    })
      .then(async (res) => {
        if (!res.ok) throw new Error(`refresh failed: ${res.status}`)
        const data = (await res.json()) as { accessToken?: string }
        if (!data.accessToken) throw new Error('refresh response missing accessToken')
        localStorage.setItem('access_token', data.accessToken)
      })
      .finally(() => {
        this.refreshPromise = null
      })
    return this.refreshPromise
  }
}

/** Singleton WebSocket instance. */
export const ws = new AirlockWS()
