import axios, { AxiosError } from 'axios'
import { fromJson } from '@bufbuild/protobuf'
import { RefreshResponseSchema } from '@/gen/airlock/v1/api_pb'

// isAuthRejection returns true only when the server actually answered with
// 401/403 — i.e. the refresh token was rejected. Transport errors (no
// response from the server at all) and 5xx (server bouncing, e.g. during
// a restart while Caddy returns 502/503) are transient and must not
// evict the user's credentials.
export function isAuthRejection(err: unknown): boolean {
  if (!(err instanceof AxiosError)) return false
  const s = err.response?.status
  return s === 401 || s === 403
}

const api = axios.create({
  baseURL: '/',
  headers: { 'Content-Type': 'application/json' },
  withCredentials: true,
})

let accessToken: string | null = null

export function setAccessToken(token: string | null) {
  accessToken = token
}

export function clearAccessToken() {
  accessToken = null
}

// Attach the in-memory Bearer token to every API request.
api.interceptors.request.use((config) => {
  if (accessToken) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }
  return config
})

// On 401, attempt to refresh the token and retry.
let refreshPromise: Promise<string> | null = null

api.interceptors.response.use(
  (res) => res,
  async (error) => {
    const original = error.config
    // Don't retry auth endpoints — 401 there means bad credentials, not expired token.
    const isAuthRoute = original.url?.startsWith('/auth/')
    if (error.response?.status !== 401 || original._retry || isAuthRoute) {
      return Promise.reject(error)
    }

    original._retry = true
    try {
      const newToken = await refreshAccessToken()
      original.headers.Authorization = `Bearer ${newToken}`
      return api(original)
    } catch (refreshErr) {
      // Server actually rejected the refresh token (401/403): credentials
      // are dead, evict and route to login. A transport error or 5xx
      // (Caddy 502/503 during an airlock restart) is transient — keep
      // the tokens so the next request after recovery works.
      if (isAuthRejection(refreshErr)) {
        clearAccessToken()
        window.location.href = '/login'
      }
      return Promise.reject(error)
    }
  },
)

export function refreshAccessToken(): Promise<string> {
  if (!refreshPromise) {
    refreshPromise = axios.post('/auth/refresh', {}, { withCredentials: true })
      .then(({ data }) => {
        const response = fromJson(RefreshResponseSchema, data)
        setAccessToken(response.accessToken)
        return response.accessToken
      })
      .finally(() => {
        refreshPromise = null
      })
  }
  return refreshPromise
}

export default api
