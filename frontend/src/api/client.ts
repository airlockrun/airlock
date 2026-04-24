import axios from 'axios'
import { fromJson } from '@bufbuild/protobuf'
import { RefreshResponseSchema } from '@/gen/airlock/v1/api_pb'

const api = axios.create({
  baseURL: '/',
  headers: { 'Content-Type': 'application/json' },
})

// Attach Bearer token to every request.
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
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
    if (!refreshPromise) {
      refreshPromise = refreshAccessToken().finally(() => {
        refreshPromise = null
      })
    }

    try {
      const newToken = await refreshPromise
      original.headers.Authorization = `Bearer ${newToken}`
      return api(original)
    } catch {
      // Refresh failed — clear tokens and redirect to login.
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      window.location.href = '/login'
      return Promise.reject(error)
    }
  },
)

async function refreshAccessToken(): Promise<string> {
  const refreshToken = localStorage.getItem('refresh_token')
  if (!refreshToken) {
    throw new Error('no refresh token')
  }
  const { data } = await axios.post('/auth/refresh', { refreshToken })
  const response = fromJson(RefreshResponseSchema, data)
  localStorage.setItem('access_token', response.accessToken)
  return response.accessToken
}

export default api
