/**
 * src/api/client.ts — ACS Sentinel API Client
 *
 * Calls the live API Gateway HTTP API over HTTPS, attaching the Cognito JWT
 * (via the Authorization header) to every request so the API Gateway Cognito
 * authorizer allows access. Base URL comes from VITE_API_URL.
 */

import { getIdToken } from './auth'

const BASE_URL = import.meta.env.VITE_API_URL ?? ''

export interface Alert {
  alert_id:    string
  timestamp:   string
  source_ip:   string
  severity:    'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  type:        string
  score:       number
  reason:      string
  status:      string
  geo_anomaly: number
  method?:     string
  metadata?:   string
}

export interface BlockedIP {
  ip:          string
  blocked_at:  string
  reason:      string
  score:       number
  ttl:         number
  severity:    string
  method?:     string
  geo_anomaly: number
}

export interface LogEntry {
  log_id:      string
  timestamp:   string
  level:       string
  source:      string
  message:     string
  source_ip:   string
  geo_anomaly: number
  score?:      number
}

async function authHeaders(): Promise<HeadersInit> {
  const token = await getIdToken()
  return token ? { Authorization: token } : {}
}

async function get<T>(path: string): Promise<T> {
  const headers = await authHeaders()
  const res = await fetch(`${BASE_URL}${path}`, { cache: 'no-store', headers })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export const fetchAlerts     = () => get<Alert[]>('/alerts')
export const fetchBlockedIPs = () => get<BlockedIP[]>('/blocked-ips')

/** One page of the log stream. `cursor` continues backwards in time;
 *  null cursor in the response means the database is exhausted. */
export interface LogPage {
  items:    LogEntry[]
  cursor:   string | null
  scanned?: number
}

export async function fetchLogPage(opts: { cursor?: string | null, q?: string, limit?: number, from?: string, to?: string } = {}): Promise<LogPage> {
  const p = new URLSearchParams()
  if (opts.cursor) p.set('cursor', opts.cursor)
  if (opts.q) p.set('q', opts.q)
  if (opts.limit) p.set('limit', String(opts.limit))
  if (opts.from) p.set('from', opts.from)
  if (opts.to) p.set('to', opts.to)
  const qs = p.toString()
  const raw = await get<LogPage | LogEntry[]>(`/logs${qs ? `?${qs}` : ''}`)
  // Tolerate the pre-pagination Lambda, which returned a bare array. The
  // dashboard then simply has no "older" pages until the API is redeployed.
  return Array.isArray(raw) ? { items: raw, cursor: null } : raw
}

/** Newest slice for the 4-second poll — same shape the poller always used. */
export const fetchLogs = async (): Promise<LogEntry[]> => (await fetchLogPage({ limit: 300 })).items

export async function unblockIP(ip: string): Promise<void> {
  const headers = await authHeaders()
  const res = await fetch(`${BASE_URL}/blocked-ips/${encodeURIComponent(ip)}`, {
    method: 'DELETE',
    headers,
  })
  if (!res.ok) throw new Error(`Unblock failed: HTTP ${res.status}`)
}

/* ── User management (admin-only) ──────────────────────────────────────────
 * All actions post to the single /users route with an `action` discriminator.
 * The Lambda re-checks cognito:groups server-side, so a non-admin token gets a
 * 403 here even though the UI never shows these controls to operators. */

export type ManagedRole = 'admin' | 'operator'

export interface ManagedAccount {
  username:  string
  federated: boolean
  status:    string
  is_admin:  boolean
}

export interface ManagedUser {
  email:         string
  invited:       boolean
  intended_role: string
  joined:        boolean
  role:          string        // 'admin' | 'operator' | '—'
  accounts:      ManagedAccount[]
  added_by:      string
  added_at:      string
}

export interface DomainAllow {
  domain:   string
  added_by: string
}

export interface UserList {
  users:   ManagedUser[]
  domains: DomainAllow[]
}

async function usersPost<T>(payload: Record<string, unknown>): Promise<T> {
  const headers = { ...(await authHeaders()), 'Content-Type': 'application/json' }
  const res = await fetch(`${BASE_URL}/users`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  })
  const data = await res.json().catch(() => ({} as any))
  if (!res.ok) throw new Error((data && (data.error as string)) || `HTTP ${res.status}`)
  return data as T
}

export const listUsers   = ()                                   => usersPost<UserList>({ action: 'list' })
export const inviteUser  = (email: string, role: ManagedRole)   => usersPost<{ status: string }>({ action: 'invite', email, role })
export const removeUser  = (email: string)                      => usersPost<{ status: string }>({ action: 'remove', email })
export const setUserRole = (email: string, role: ManagedRole)   => usersPost<{ status: string, note?: string }>({ action: 'setrole', email, role })
