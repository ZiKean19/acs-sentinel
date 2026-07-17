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

export async function fetchLogPage(opts: { cursor?: string | null, q?: string, limit?: number } = {}): Promise<LogPage> {
  const p = new URLSearchParams()
  if (opts.cursor) p.set('cursor', opts.cursor)
  if (opts.q) p.set('q', opts.q)
  if (opts.limit) p.set('limit', String(opts.limit))
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
