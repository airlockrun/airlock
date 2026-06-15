// WebAuthn ceremony helpers. The begin/finish endpoints exchange raw WebAuthn
// JSON (not proto): begin returns { ceremony_id, options } where options is the
// go-webauthn CredentialCreation/Assertion ({ publicKey: ... }); finish takes
// the browser's attestation/assertion in the body and the ceremony id in the
// query. @simplewebauthn/browser drives the navigator.credentials calls.
import { startRegistration, startAuthentication } from '@simplewebauthn/browser'
import { fromJson } from '@bufbuild/protobuf'
import api from '@/api/client'
import { LoginResponseSchema, RegisterPasskeyResponseSchema } from '@/gen/airlock/v1/api_pb'
import type { LoginResponse } from '@/gen/airlock/v1/api_pb'
import type { Passkey } from '@/gen/airlock/v1/types_pb'

// registerPasskey runs the registration ceremony for the authenticated user and
// returns the created passkey. name is the user-facing label.
export async function registerPasskey(name: string): Promise<Passkey> {
  const { data: begin } = await api.post('/api/v1/me/passkeys/register/begin')
  const attResp = await startRegistration({ optionsJSON: begin.options.publicKey })
  const q = `ceremony_id=${encodeURIComponent(begin.ceremony_id)}&name=${encodeURIComponent(name)}`
  const { data } = await api.post(`/api/v1/me/passkeys/register/finish?${q}`, attResp)
  return fromJson(RegisterPasskeyResponseSchema, data).passkey!
}

// passkeyLogin runs the login ceremony. An empty email is a usernameless
// (discoverable) login; a provided email scopes to that account. Returns the
// LoginResponse (tokens + user).
export async function passkeyLogin(email?: string): Promise<LoginResponse> {
  const { data: begin } = await api.post('/auth/passkey/login/begin', email ? { email } : {})
  const asseResp = await startAuthentication({ optionsJSON: begin.options.publicKey })
  const q = `ceremony_id=${encodeURIComponent(begin.ceremony_id)}`
  const { data } = await api.post(`/auth/passkey/login/finish?${q}`, asseResp)
  return fromJson(LoginResponseSchema, data)
}
