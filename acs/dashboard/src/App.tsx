import { useState, useEffect, useCallback, useMemo } from 'react'
import { Shield, Activity, Ban, Bell, Terminal, Wifi, WifiOff, LogOut, Sun, Moon, RefreshCw, Info, Globe, Clock, AlertTriangle, History } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine, AreaChart, Area, Legend } from 'recharts'
import { fetchAlerts, fetchBlockedIPs, fetchLogs, unblockIP } from './api/client'
import { useSSE } from './hooks/useSSE'

export type Alert     = { alert_id: string, timestamp: string, source_ip: string, severity: string, type: string, score: number, reason: string, method: string, geo_anomaly: number, metadata?: string }
export type BlockedIP = { ip: string, blocked_at: string, reason: string, score: number, severity: string, ttl: number, geo_anomaly: number }
export type LogEntry  = { log_id: string, timestamp: string, level: string, source: string, message: string, source_ip: string, geo_anomaly: number, score?: number }

const MYT = 'Asia/Kuala_Lumpur'

function parseTS(ts: string): Date {
  if (!ts) return new Date()
  return new Date(ts.replace('+00:00', 'Z'))
}
function formatTime(ts: string): string {
  const d = parseTS(ts)
  const dateStr = `${(d.getMonth() + 1).toString().padStart(2, '0')}/${d.getDate().toString().padStart(2, '0')}`
  const timeStr = d.toLocaleTimeString('en-MY', { timeZone: MYT, hour12: false })
  return `${dateStr} ${timeStr}`
}

type Theme = 'dark' | 'light'
function applyTheme(theme: Theme) { document.documentElement.setAttribute('data-theme', theme) }

function LoginScreen({ onLogin, theme, toggleTheme }: { onLogin: () => void, theme: Theme, toggleTheme: () => void }) {
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [err,  setErr]  = useState('')
  const [loading, setLoading] = useState(false)

  const handleLogin = async () => {
    setLoading(true); setErr('')
    await new Promise(r => setTimeout(r, 800))
    if (user === 'admin' && pass === 'sentinel') { onLogin() }
    else { setErr('ACCESS DENIED — Invalid credentials'); setLoading(false) }
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-base)' }}>
      <div style={{ position: 'fixed', top: 16, right: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
        <Sun size={12} color="var(--accent-amber)" />
        <button className="theme-toggle" onClick={toggleTheme} title="Toggle theme" />
        <Moon size={12} color="var(--text-muted)" />
      </div>
      <div className="glass-panel slide-in-right" style={{ width: 360, padding: '40px 32px', background: 'var(--bg-panel)', border: '1px solid var(--border)' }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ width: 56, height: 56, margin: '0 auto 16px', background: 'rgba(0,200,100,0.1)', border: '1px solid var(--accent-green)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Shield size={28} color="var(--accent-green)" />
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--accent-green)', letterSpacing: 4 }}>ACS SENTINEL</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 4, letterSpacing: 2 }}>AUTOMATED CLOUD SECURITY</div>
        </div>
        <div style={{ marginBottom: 16 }}>
          <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 2, display: 'block', marginBottom: 6 }}>USERNAME</label>
          <input value={user} onChange={e => setUser(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleLogin()}
            style={{ width: '100%', padding: '10px 12px', background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 13, outline: 'none' }} />
        </div>
        <div style={{ marginBottom: 24 }}>
          <label style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', letterSpacing: 2, display: 'block', marginBottom: 6 }}>PASSWORD</label>
          <input type="password" value={pass} onChange={e => setPass(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleLogin()}
            style={{ width: '100%', padding: '10px 12px', background: 'var(--bg-card)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 13, outline: 'none' }} />
        </div>
        {err && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-red)', marginBottom: 16, padding: '8px 12px', background: 'rgba(220,38,38,0.08)', border: '1px solid rgba(220,38,38,0.3)' }}>{err}</div>}
        <button onClick={handleLogin} disabled={loading}
          style={{ width: '100%', padding: '12px', background: loading ? 'rgba(0,200,100,0.08)' : 'rgba(0,200,100,0.12)', border: '1px solid var(--accent-green)', color: 'var(--accent-green)', fontFamily: 'var(--font-mono)', fontSize: 12, letterSpacing: 3, cursor: loading ? 'wait' : 'pointer' }}>
          {loading ? 'AUTHENTICATING...' : 'AUTHENTICATE'}
        </button>
        <div style={{ marginTop: 16, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', textAlign: 'center' }}>DEFAULT: admin / sentinel</div>
      </div>
    </div>
  )
}

function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = { CRITICAL: 'var(--accent-red)', HIGH: '#f97316', MEDIUM: 'var(--accent-amber)', LOW: 'var(--accent-green)' }
  const color = colors[severity] || 'var(--text-muted)'
  return (
    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, letterSpacing: 1, color, border: `1px solid ${color}`, padding: '2px 6px', background: `${color}18`, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      {severity === 'CRITICAL' && <AlertTriangle size={10} />}{severity}
    </span>
  )
}

function IPWithGeo({ ip, geoAnomaly }: { ip: string, geoAnomaly?: number }) {
  const isMY = geoAnomaly !== 1
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
      <span title={isMY ? 'Malaysia' : 'Foreign IP'}>{isMY ? '🇲🇾' : <Globe size={11} color="var(--accent-blue)" />}</span>
      <span style={{ color: 'var(--accent-blue)' }}>{ip}</span>
    </div>
  )
}

function RiskCard({ alert, onClose }: { alert: Alert, onClose: () => void }) {
  return (
    <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 20 }} onClick={onClose}>
      <div className="glass-panel slide-in-right" style={{ width: '100%', maxWidth: 500, background: 'var(--bg-panel)', border: '1px solid var(--border)', position: 'relative' }} onClick={e => e.stopPropagation()}>
        <div style={{ height: 4, background: alert.severity === 'CRITICAL' ? 'var(--accent-red)' : 'var(--accent-amber)' }} />
        <div style={{ padding: 24 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 20 }}>
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)', letterSpacing: 2 }}>THREAT ANALYSIS REPORT</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 18, color: 'var(--text-primary)', marginTop: 4, fontWeight: 'bold' }}>{alert.type}</div>
            </div>
            <SeverityBadge severity={alert.severity} />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 24 }}>
            <div style={{ background: 'var(--bg-card)', padding: 12, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 9, color: 'var(--text-dim)', marginBottom: 4 }}>SOURCE IP</div>
              <IPWithGeo ip={alert.source_ip} geoAnomaly={alert.geo_anomaly} />
            </div>
            <div style={{ background: 'var(--bg-card)', padding: 12, border: '1px solid var(--border)' }}>
              <div style={{ fontSize: 9, color: 'var(--text-dim)', marginBottom: 4 }}>ANOMALY SCORE</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--accent-blue)' }}>{alert.score.toFixed(4)}</div>
            </div>
          </div>
          <div style={{ marginBottom: 24 }}>
            <div style={{ fontSize: 10, color: 'var(--text-dim)', marginBottom: 8, fontFamily: 'var(--font-mono)' }}>DETECTION REASON</div>
            <div style={{ background: 'rgba(0,0,0,0.2)', padding: 12, borderLeft: '2px solid var(--accent-blue)', color: 'var(--text-muted)', fontSize: 11, fontStyle: 'italic' }}>"{alert.reason}"</div>
          </div>
          <button onClick={onClose} style={{ width: '100%', padding: 12, background: 'var(--border)', border: 'none', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 11, cursor: 'pointer', letterSpacing: 2 }}>
            DISMISS REPORT
          </button>
        </div>
      </div>
    </div>
  )
}

function AlertBanner({ alerts }: { alerts: Alert[] }) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  alerts.forEach(a => { if (a.severity in counts) counts[a.severity as keyof typeof counts]++ })
  return (
    <div style={{ display: 'flex', gap: 12, padding: '12px 0' }}>
      {Object.entries(counts).map(([sev, count]) => {
        const colors: Record<string, string> = { CRITICAL: 'var(--accent-red)', HIGH: '#f97316', MEDIUM: 'var(--accent-amber)', LOW: 'var(--accent-green)' }
        const color = colors[sev]
        return (
          <div className="glass-panel" key={sev} style={{ flex: 1, padding: '14px 16px', background: count > 0 ? `${color}12` : 'var(--bg-card)', border: `1px solid ${count > 0 ? color : 'var(--border)'}`, display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 22, color: count > 0 ? color : 'var(--text-dim)', fontWeight: 'bold' }}>{count}</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', letterSpacing: 2 }}>{sev}</div>
          </div>
        )
      })}
    </div>
  )
}

function RiskGauge({ logs }: { logs: LogEntry[] }) {
  const currentScore = useMemo(() => {
    if (!logs || logs.length === 0) return 0.1
    const sorted = [...logs].sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    return typeof sorted[0].score === 'number' ? sorted[0].score : 0.1
  }, [logs])

  let riskPercent = 0
  if (currentScore >= 0.1)       { riskPercent = 0 }
  else if (currentScore >= 0.031) { riskPercent = ((0.1 - currentScore) / (0.1 - 0.031)) * 50 }
  else { riskPercent = 50 + ((0.031 - Math.max(-1.0, currentScore)) / (0.031 + 1.0)) * 50 }
  riskPercent = Math.min(riskPercent, 100)

  const arcLength = 126
  const strokeDashoffset = arcLength - (arcLength * riskPercent) / 100
  const color = riskPercent > 80 ? 'var(--accent-red)' : riskPercent > 40 ? 'var(--accent-amber)' : 'var(--accent-green)'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12 }}>
      <svg width="120" height="65" viewBox="0 0 100 55">
        <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke="var(--bg-panel)" strokeWidth="10" strokeLinecap="round" />
        <path d="M 10 50 A 40 40 0 0 1 90 50" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" strokeDasharray={arcLength} strokeDashoffset={strokeDashoffset} style={{ transition: 'stroke-dashoffset 0.5s ease-out, stroke 0.5s' }} />
        <text x="50" y="45" textAnchor="middle" fill={color} fontSize="16" fontFamily="var(--font-mono)" fontWeight="bold">{riskPercent.toFixed(1)}%</text>
      </svg>
      <div style={{ textAlign: 'center', fontFamily: 'var(--font-mono)' }}>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', letterSpacing: 2, marginBottom: 4 }}>LIVE AI RISK</div>
        <div style={{ fontSize: 11, color: 'var(--text-primary)' }}>{currentScore.toFixed(4)}</div>
      </div>
    </div>
  )
}

function AnomalyChart({ alerts }: { alerts: Alert[] }) {
  const data = useMemo(() => {
    return [...alerts]
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
      .slice(-40)
      .map(a => ({ time: parseTS(a.timestamp).getTime(), score: Math.abs(a.score), severity: a.severity }))
  }, [alerts])

  return (
    <div style={{ height: 250 }}>
      {data.length === 0 ? (
        <div style={{ height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)' }}>
          NO ANOMALY DATA — RUN ATTACK SIMULATOR
        </div>
      ) : (
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, bottom: 0, left: -20 }}>
            <defs>
              <linearGradient id="colorScore" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="var(--accent-blue)" stopOpacity={0.3} />
                <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="time" type="number" domain={['auto', 'auto']} scale="time"
              tickFormatter={(t) => new Date(t).toLocaleTimeString('en-MY', { hour: '2-digit', minute: '2-digit', timeZone: MYT, hour12: false })}
              tick={{ fill: 'var(--chart-tick)', fontSize: 9, fontFamily: 'Share Tech Mono' } as any} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: 'var(--chart-tick)', fontSize: 9, fontFamily: 'Share Tech Mono' } as any} axisLine={false} tickLine={false} />
            <Tooltip
              labelFormatter={(t) => new Date(t).toLocaleTimeString('en-MY', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: MYT, hour12: false })}
              contentStyle={{ background: 'var(--chart-tooltip-bg)', border: '1px solid var(--border)', fontFamily: 'Share Tech Mono', fontSize: 10 }}
              labelStyle={{ color: 'var(--text-muted)', marginBottom: 4 }} />
            <Legend wrapperStyle={{ fontSize: 10, fontFamily: 'var(--font-mono)', paddingTop: 10 }} />
            <ReferenceLine y={0.5} stroke="var(--accent-red)" strokeOpacity={0.4} strokeDasharray="3 3" label={{ position: 'right', value: 'ALERT', fill: 'var(--accent-red)', fontSize: 9 }} />
            <Area type="monotone" dataKey="score" stroke="var(--accent-blue)" fillOpacity={1} fill="url(#colorScore)" strokeWidth={2} name="Risk Score" />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}

function Spinner() {
  return (
    <div style={{ padding: 32, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10 }}>
      <RefreshCw size={14} color="var(--accent-green)" style={{ animation: 'spin 1s linear infinite' }} />
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>LOADING...</span>
    </div>
  )
}

function LogFeed({ logs, loading, error, onRefresh }: { logs: LogEntry[], loading: boolean, error: boolean, onRefresh: () => void }) {
  const [searchQuery, setSearchQuery] = useState('')

  const filteredLogs = useMemo(() => {
    if (!searchQuery) return logs
    const keywords = searchQuery.toLowerCase().split(/\s+/).filter(k => k.length > 0)
    return logs.filter(log => {
      const text = [formatTime(log.timestamp), log.level, log.source_ip, log.message, log.source].join(' ').toLowerCase()
      return keywords.every(k => text.includes(k))
    })
  }, [logs, searchQuery])

  const sortedLogs = useMemo(() => [...filteredLogs].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 1000), [filteredLogs])

  const levelColor = (level: string) => {
    const map: Record<string, string> = { CRITICAL: 'var(--accent-red)', HIGH: '#f97316', MEDIUM: '#eab308', WARN: '#64748b', AUDIT: '#a855f7' }
    return map[level] || 'var(--accent-green)'
  }

  if (loading && logs.length === 0) return <Spinner />
  if (error   && logs.length === 0) return (
    <div style={{ padding: 16, display: 'flex', alignItems: 'center', gap: 12, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
      <span style={{ color: 'var(--accent-red)' }}>CONNECTION ERROR — Flask backend unreachable</span>
      <button onClick={onRefresh} style={{ padding: '4px 10px', background: 'transparent', border: '1px solid var(--border-bright)', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10, fontFamily: 'var(--font-mono)' }}>RETRY</button>
    </div>
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', flexWrap: 'wrap', gap: 12, background: 'var(--bg-card)', alignItems: 'center' }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <Terminal size={12} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
          <input type="text" placeholder="FILTER BY KEYWORD, IP, LEVEL..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
            style={{ width: '100%', padding: '10px 12px 10px 32px', background: 'var(--bg-base)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 11, outline: 'none' }} />
          {searchQuery && <button onClick={() => setSearchQuery('')} style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 14 }}>x</button>}
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{sortedLogs.length} / {logs.length} RECORDS</div>
      </div>
      <div style={{ height: 600, overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
        {sortedLogs.length === 0 ? (
          <div style={{ padding: '32px 16px', color: 'var(--text-dim)', textAlign: 'center' }}>WAITING FOR LOG DATA...</div>
        ) : (
          sortedLogs.map((log, i) => (
            <div key={log.log_id ? `${log.log_id}-${i}` : `log-${i}`}
              style={{ padding: '8px 16px', borderBottom: '1px solid var(--bg-base)', display: 'flex', gap: 16, alignItems: 'flex-start', background: log.level === 'CRITICAL' ? 'rgba(220,38,38,0.06)' : log.level === 'AUDIT' ? 'rgba(168,85,247,0.06)' : 'transparent' }}>
              <span style={{ color: 'var(--text-muted)', flexShrink: 0, width: 110, fontSize: 10 }}>{formatTime(log.timestamp)}</span>
              <span style={{ color: levelColor(log.level), flexShrink: 0, width: 75, fontWeight: 'bold' }}>[{log.level}]</span>
              <span style={{ flexShrink: 0, width: 140 }}><IPWithGeo ip={log.source_ip} geoAnomaly={log.geo_anomaly} /></span>
              <span style={{ color: 'var(--text-primary)', wordBreak: 'break-all', flex: 1 }}>{log.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function BlocklistPanel({ ips, logs, loading, error, onUnblock, onRefresh }: { ips: BlockedIP[], logs: LogEntry[], loading: boolean, error: boolean, onUnblock: (ip: string) => void, onRefresh: () => void }) {
  const [searchQuery, setSearchQuery] = useState('')
  const [now, setNow] = useState(Date.now() / 1000)

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => clearInterval(timer)
  }, [])

  const sortedIPs = useMemo(() => {
    const q = searchQuery.toLowerCase()
    return [...ips]
      .filter(item => !q || item.ip.toLowerCase().includes(q) || item.reason.toLowerCase().includes(q) || item.severity.toLowerCase().includes(q))
      .sort((a, b) => (b.blocked_at || '').localeCompare(a.blocked_at || ''))
  }, [ips, searchQuery])

  const auditLogs = useMemo(() => logs.filter(l => l.level === 'AUDIT').slice(0, 50), [logs])

  if (loading && ips.length === 0) return <Spinner />

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, background: 'var(--bg-card)', alignItems: 'center' }}>
        <div style={{ flex: 1, position: 'relative' }}>
          <input type="text" placeholder="FILTER BY IP OR REASON..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
            style={{ width: '100%', padding: '8px 12px', background: 'var(--bg-base)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 11, outline: 'none' }} />
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>{sortedIPs.length} BLOCKED</div>
      </div>
      <div style={{ height: 350, overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
        {sortedIPs.length === 0 ? (
          <div style={{ padding: '32px 16px', color: 'var(--text-dim)', textAlign: 'center' }}>SYSTEM CLEAN — NO BLOCKED IPs</div>
        ) : (
          sortedIPs.map((item, i) => {
            const timeLeft = item.ttl ? Math.max(0, item.ttl - now) : 0
            const hours = Math.floor(timeLeft / 3600)
            const mins  = Math.floor((timeLeft % 3600) / 60)
            const secs  = Math.floor(timeLeft % 60)
            return (
              <div key={`${item.ip}-${i}`} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-card)' }}>
                <Ban size={12} color="var(--accent-red)" />
                <div style={{ minWidth: 140 }}><IPWithGeo ip={item.ip} geoAnomaly={item.geo_anomaly} /></div>
                <div style={{ minWidth: 80 }}><SeverityBadge severity={item.severity} /></div>
                <span style={{ color: 'var(--text-muted)', flex: 1, fontSize: 10 }}>{item.reason}</span>
                <div style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, minWidth: 90 }}>
                  <Clock size={10} color="var(--text-dim)" />
                  {timeLeft > 0 ? <span style={{ color: 'var(--text-dim)' }}>{hours}h {mins}m {secs}s</span> : <span style={{ color: 'var(--accent-amber)' }}>EXPIRED</span>}
                </div>
                <button onClick={() => onUnblock(item.ip)} style={{ padding: '4px 12px', background: 'transparent', border: '1px solid var(--border-bright)', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 10, fontFamily: 'var(--font-mono)', marginLeft: 8 }}>UNBLOCK</button>
              </div>
            )
          })
        )}
      </div>
      <div style={{ borderTop: '2px solid var(--border)', flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '8px 16px', background: 'rgba(168,85,247,0.08)', display: 'flex', alignItems: 'center', gap: 8, borderBottom: '1px solid var(--border)' }}>
          <History size={12} color="#a855f7" />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#a855f7', fontWeight: 'bold', letterSpacing: 1 }}>REMEDIATION HISTORY</span>
          <span style={{ marginLeft: 'auto', fontSize: 9, color: 'var(--text-dim)' }}>{auditLogs.length} EVENTS</span>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
          {auditLogs.length === 0 ? (
            <div style={{ padding: '24px 16px', color: 'var(--text-dim)', fontStyle: 'italic', textAlign: 'center' }}>NO RECENT REMEDIATION ACTIONS.</div>
          ) : (
            auditLogs.map((entry, i) => (
              <div key={i} style={{ padding: '6px 16px', borderBottom: '1px solid var(--bg-base)', display: 'flex', gap: 12 }}>
                <span style={{ color: 'var(--text-dim)', flexShrink: 0, width: 100 }}>{formatTime(entry.timestamp)}</span>
                <span style={{ color: '#a855f7', flexShrink: 0, width: 45 }}>[AUDIT]</span>
                <span style={{ color: 'var(--text-primary)', flex: 1 }}>{entry.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

function Panel({ title, icon, children, accent, extra }: { title: string, icon: React.ReactNode, children: React.ReactNode, accent?: string, extra?: React.ReactNode }) {
  return (
    <div className="glass-panel" style={{ background: 'var(--bg-panel)', border: `1px solid ${accent || 'var(--border)'}`, boxShadow: accent ? `0 0 20px ${accent}12` : 'none' }}>
      <div style={{ padding: '10px 16px', borderBottom: `1px solid ${accent || 'var(--border)'}`, display: 'flex', alignItems: 'center', gap: 8, background: accent ? `${accent}08` : 'transparent' }}>
        {icon}<span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: 2, color: accent || 'var(--text-muted)' }}>{title}</span>
        {extra && <div style={{ marginLeft: 'auto' }}>{extra}</div>}
      </div>
      <div>{children}</div>
    </div>
  )
}

function Dashboard({ onLogout, theme, toggleTheme }: { onLogout: () => void, theme: Theme, toggleTheme: () => void }) {
  const { data: alerts,    status: alertsStatus,  reset: resetAlerts  } = useSSE<Alert[]>('/api/stream/alerts',      [], { maxItems: 5000 })
  const { data: blockedIPs, status: blockedStatus, reset: resetBlocked } = useSSE<BlockedIP[]>('/api/stream/blocked-ips', [], { maxItems: 5000 })
  const { data: logs,      status: logsStatus,    reset: resetLogs    } = useSSE<LogEntry[]>('/api/stream/logs',        [], { maxItems: 5000 })

  const connected  = alertsStatus === 'open' && logsStatus === 'open' && blockedStatus === 'open'
  const anyError   = alertsStatus === 'error' || logsStatus === 'error' || blockedStatus === 'error'
  const ipsError   = blockedStatus === 'error'
  const logsError  = logsStatus === 'error'

  const [tab, setTab]                     = useState<'overview' | 'logs' | 'blocklist'>('overview')
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)

  const handleUnblock = async (ip: string) => { await unblockIP(ip) }
  const criticalAlerts = (alerts as Alert[]).filter(a => a.severity === 'CRITICAL')

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column' }}>
      {selectedAlert && <RiskCard alert={selectedAlert} onClose={() => setSelectedAlert(null)} />}

      <div className="glass-panel" style={{ height: 48, background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', padding: '0 20px', gap: 16, flexShrink: 0 }}>
        <Shield size={16} color="var(--accent-green)" />
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--accent-green)', letterSpacing: 3 }}>ACS SENTINEL</span>
        <div style={{ flex: 1 }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Sun size={11} color="var(--accent-amber)" />
          <button className="theme-toggle" onClick={toggleTheme} title="Toggle theme" />
          <Moon size={11} color="var(--text-muted)" />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {connected ? <Wifi size={12} color="var(--accent-green)" /> : anyError ? <WifiOff size={12} color="var(--accent-red)" /> : <RefreshCw size={12} color="var(--accent-amber)" style={{ animation: 'spin 1s linear infinite' }} />}
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: connected ? 'var(--accent-green)' : anyError ? 'var(--accent-red)' : 'var(--accent-amber)' }}>
            {connected ? 'STREAMING' : anyError ? 'RECONNECTING' : 'CONNECTING'}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)', animation: 'pulse-green 2s infinite' }} />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>LIVE</span>
        </div>
        <button onClick={onLogout} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}><LogOut size={16} /></button>
      </div>

      {criticalAlerts.length > 0 && (
        <div style={{ background: 'rgba(220,38,38,0.12)', borderBottom: '1px solid var(--accent-red)', padding: '8px 20px', display: 'flex', alignItems: 'center', gap: 8, fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent-red)', cursor: 'pointer' }} onClick={() => setSelectedAlert(criticalAlerts[0])}>
          <Bell size={12} />CRITICAL THREAT DETECTED — {criticalAlerts[0].type} from {criticalAlerts[0].source_ip}
          <span style={{ marginLeft: 'auto', fontSize: 9 }}>VIEW REPORT</span>
        </div>
      )}

      <div className="glass-panel" style={{ display: 'flex', padding: '0 20px', background: 'var(--bg-panel)', borderBottom: '1px solid var(--border)' }}>
        {([{ id: 'overview', label: 'OVERVIEW', icon: <Activity size={12} /> }, { id: 'logs', label: 'LOG STREAM', icon: <Terminal size={12} /> }, { id: 'blocklist', label: 'BLOCKLIST', icon: <Ban size={12} /> }] as const).map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{ padding: '10px 20px', background: 'transparent', border: 'none', borderBottom: tab === t.id ? '2px solid var(--accent-green)' : '2px solid transparent', color: tab === t.id ? 'var(--accent-green)' : 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: 1 }}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, padding: 20, overflow: 'auto', background: 'var(--bg-base)' }}>
        {tab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <AlertBanner alerts={alerts as Alert[]} />
            <Panel title="SECURITY METRICS HUB (MYT)" icon={<Activity size={12} color="var(--accent-blue)" />} accent="var(--accent-blue)">
              <div style={{ padding: '16px 8px', display: 'flex', gap: 16 }}>
                <div style={{ flex: 1 }}><AnomalyChart alerts={alerts as Alert[]} /></div>
                <div style={{ width: 140, borderLeft: '1px solid var(--border)', paddingLeft: 16, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <RiskGauge logs={logs as LogEntry[]} />
                </div>
              </div>
            </Panel>
            <Panel title="RECENT ALERTS" icon={<Bell size={12} color="var(--accent-amber)" />} accent="var(--accent-amber)"
              extra={<span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-dim)' }}>CLICK FOR RISK CARD</span>}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                {(alerts as Alert[]).length === 0 ? (
                  <div style={{ padding: 16, color: 'var(--text-dim)' }}>NO ALERTS — SYSTEM NOMINAL</div>
                ) : (
                  [...(alerts as Alert[])].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 15).map((alert, i) => {
                    const isML      = alert.method === 'isolation_forest'
                    const methColor = isML ? '#a855f7' : 'var(--text-muted)'
                    return (
                      <div key={i} onClick={() => setSelectedAlert(alert)} style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: '10px 16px', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                          <SeverityBadge severity={alert.severity} />
                          <IPWithGeo ip={alert.source_ip} geoAnomaly={alert.geo_anomaly} />
                          <span style={{ color: 'var(--text-primary)', flex: 1, fontWeight: 'bold' }}>{alert.type}</span>
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: methColor, border: `1px solid ${methColor}66`, padding: '2px 6px', background: `${methColor}15` }}>[{isML ? 'ML' : 'RULE'}]</span>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 4, color: 'var(--text-dim)', fontSize: 10 }}><Info size={10} />score: {alert.score.toFixed(3)}</div>
                          <span style={{ color: 'var(--text-dim)', fontSize: 10 }}>{formatTime(alert.timestamp)}</span>
                        </div>
                        <div style={{ paddingLeft: 60, fontSize: 10, color: 'var(--text-dim)' }}>{alert.reason}</div>
                      </div>
                    )
                  })
                )}
              </div>
            </Panel>
          </div>
        )}

        {tab === 'logs' && (
          <Panel title="LIVE LOG STREAM" icon={<Terminal size={12} color="var(--accent-green)" />} accent="var(--accent-green)"
            extra={<button onClick={resetLogs} style={{ padding: '2px 8px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 9, fontFamily: 'var(--font-mono)' }}>RECONNECT</button>}>
            <LogFeed logs={logs as LogEntry[]} loading={logsStatus === 'connecting'} error={logsError} onRefresh={resetLogs} />
          </Panel>
        )}

        {tab === 'blocklist' && (
          <Panel title="BLOCKED IP ADDRESSES" icon={<Ban size={12} color="var(--accent-red)" />} accent="var(--accent-red)"
            extra={<button onClick={resetBlocked} style={{ padding: '2px 8px', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-dim)', cursor: 'pointer', fontSize: 9, fontFamily: 'var(--font-mono)' }}>RECONNECT</button>}>
            <BlocklistPanel ips={blockedIPs as BlockedIP[]} logs={logs as LogEntry[]} loading={blockedStatus === 'connecting'} error={ipsError} onUnblock={handleUnblock} onRefresh={resetBlocked} />
          </Panel>
        )}
      </div>

      <div style={{ height: 24, background: 'var(--bg-panel)', borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', padding: '0 16px', gap: 20, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)' }}>
        <Shield size={10} color="var(--accent-green)" /><span>AUTO-MITIGATION ACTIVE</span>
        <span style={{ flex: 1 }} /><span>ACS Sentinel · MYT (UTC+8)</span>
      </div>
    </div>
  )
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const [theme, setTheme] = useState<Theme>(() => {
    try { return (localStorage.getItem('acs-theme') as Theme) || 'dark' } catch { return 'dark' }
  })
  useEffect(() => { applyTheme(theme); try { localStorage.setItem('acs-theme', theme) } catch { } }, [theme])
  const toggleTheme = useCallback(() => setTheme(t => t === 'dark' ? 'light' : 'dark'), [])
  if (!authenticated) return <LoginScreen onLogin={() => setAuthenticated(true)} theme={theme} toggleTheme={toggleTheme} />
  return <Dashboard onLogout={() => setAuthenticated(false)} theme={theme} toggleTheme={toggleTheme} />
}
