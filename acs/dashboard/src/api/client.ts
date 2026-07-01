/**
 * src/api/client.ts — ACS Sentinel API Client
 * Uses Vite proxy (/api -> http://localhost:5000) to avoid CORS issues.
 */

const BASE_URL = '/api'

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

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`)
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export const fetchAlerts     = () => get<Alert[]>('/alerts')
export const fetchBlockedIPs = () => get<BlockedIP[]>('/blocked-ips')
export const fetchLogs       = () => get<LogEntry[]>('/logs')

export async function unblockIP(ip: string): Promise<void> {
  const res = await fetch(`${BASE_URL}/blocked-ips/${encodeURIComponent(ip)}`, {
    method: 'DELETE',
  })
  if (!res.ok) throw new Error(`Unblock failed: HTTP ${res.status}`)
}
