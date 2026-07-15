import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import {
  Shield, ShieldCheck, Activity, Ban, Bell, Terminal, LogOut, Sun, Moon,
  RefreshCw, X, Search, AlertTriangle, AlertCircle, MinusCircle,
  CheckCircle2, History, Wifi, WifiOff, Inbox,
} from 'lucide-react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine, CartesianGrid,
} from 'recharts'
import { fetchAlerts, fetchBlockedIPs, fetchLogs, unblockIP } from './api/client'
import type { Alert, BlockedIP, LogEntry } from './api/client'
import { usePolling } from './hooks/usePolling'
import { signIn, signOut } from './api/auth'

export type { Alert, BlockedIP, LogEntry }

/* ══════════════════════════════════════════════════════════════════════════
   Constants & helpers
   ══════════════════════════════════════════════════════════════════════════ */

const MYT = 'Asia/Kuala_Lumpur'

/** Isolation Forest alert threshold — must mirror IF_THRESHOLD in the
 *  Detection Lambda. Scores below this are treated as anomalous. */
const IF_THRESHOLD = -0.02

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
function formatClock(t: number): string {
  return new Date(t).toLocaleTimeString('en-MY', { timeZone: MYT, hour12: false, hour: '2-digit', minute: '2-digit' })
}
/** Minus sign (U+2212) rather than hyphen: aligns with tabular figures. */
const num = (n: number, dp = 4) => n.toFixed(dp).replace('-', '−')
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many)

type Theme = 'dark' | 'light'
function applyTheme(theme: Theme) { document.documentElement.setAttribute('data-theme', theme) }

type SevKey = 'critical' | 'high' | 'medium' | 'low' | 'unknown'
const sevKey = (s: string): SevKey => {
  const k = (s || '').toLowerCase()
  return (['critical', 'high', 'medium', 'low'].includes(k) ? k : 'unknown') as SevKey
}
const titleCase = (s: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1).toLowerCase() : 'Unknown')

/* ══════════════════════════════════════════════════════════════════════════
   Primitives
   ══════════════════════════════════════════════════════════════════════════ */

/** Severity is carried by colour AND icon AND word — never colour alone.
 *  Roughly 8% of men have some colour-vision deficiency; a red/amber pill
 *  pair is exactly the confusion these users hit. */
function SeverityPill({ severity }: { severity: string }) {
  const k = sevKey(severity)
  const Icon = { critical: AlertTriangle, high: AlertCircle, medium: MinusCircle, low: CheckCircle2, unknown: MinusCircle }[k]
  return (
    <span className={`sev sev-${k}`}>
      <Icon size={11} strokeWidth={2.6} aria-hidden="true" />
      {titleCase(severity)}
    </span>
  )
}

function IpCell({ ip, geoAnomaly }: { ip: string, geoAnomaly?: boolean | string }) {
  const foreign = geoAnomaly === true || geoAnomaly === 'true'
  return (
    <span className="ip" title={foreign ? `${ip} — originates outside Malaysia` : `${ip} — Malaysian address`}>
      <span className="flagmark" aria-hidden="true">{foreign ? '🌐' : '🇲🇾'}</span>
      {ip}
      {foreign && <span className="foreign">Foreign</span>}
    </span>
  )
}

function ThemeButton({ theme, toggleTheme }: { theme: Theme, toggleTheme: () => void }) {
  return (
    <button className="btn ghost" onClick={toggleTheme}
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
      {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
    </button>
  )
}

function Spinner({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="empty">
      <RefreshCw size={18} className="spin icon" aria-hidden="true" />
      <p style={{ marginBottom: 0 }}>{label}</p>
    </div>
  )
}

/** Empty states are an invitation, not a shrug: say what happened, why it's
 *  fine (or not), and offer the next action. */
function EmptyState({ icon, title, body, action }: {
  icon: React.ReactNode, title: string, body: string, action?: React.ReactNode
}) {
  return (
    <div className="empty">
      <div className="icon" aria-hidden="true">{icon}</div>
      <h4>{title}</h4>
      <p>{body}</p>
      {action}
    </div>
  )
}

function SearchBox({ value, onChange, placeholder }: {
  value: string, onChange: (v: string) => void, placeholder: string
}) {
  return (
    <div className="search">
      <Search size={15} aria-hidden="true" />
      <input type="text" value={value} placeholder={placeholder}
        onChange={e => onChange(e.target.value)} aria-label={placeholder} />
      {value && (
        <button className="clear" onClick={() => onChange('')} aria-label="Clear filter" title="Clear">
          <X size={14} />
        </button>
      )}
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Login
   ══════════════════════════════════════════════════════════════════════════ */

function LoginScreen({ onLogin, theme, toggleTheme }: { onLogin: () => void, theme: Theme, toggleTheme: () => void }) {
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [err, setErr] = useState('')
  const [loading, setLoading] = useState(false)

  const handleLogin = async () => {
    if (!user || !pass) { setErr('Enter both your username and password.'); return }
    setLoading(true); setErr('')
    try {
      await signIn(user, pass)
      onLogin()
    } catch (e: any) {
      // Plain language, and it says what to do next. "ACCESS DENIED" tells the
      // user they failed; it does not tell them how to succeed.
      setErr(e?.message || 'We couldn’t sign you in. Check your username and password, then try again.')
      setLoading(false)
    }
  }

  return (
    <div className="login-wrap">
      <div style={{ position: 'fixed', top: 16, right: 16 }}>
        <ThemeButton theme={theme} toggleTheme={toggleTheme} />
      </div>

      <div className="login">
        <div className="login-mark"><Shield size={22} strokeWidth={2.2} /></div>
        <h1>Sign in to ACS Sentinel</h1>

        {err && (
          <div className="form-error" role="alert">
            <AlertTriangle size={15} aria-hidden="true" />
            <span>{err}</span>
          </div>
        )}

        <div className="field">
          <label htmlFor="username">Username</label>
          <input id="username" type="text" value={user} autoComplete="username" autoFocus
            onChange={e => setUser(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') handleLogin() }} />
        </div>
        <div className="field">
          <label htmlFor="password">Password</label>
          <input id="password" type="password" value={pass} autoComplete="current-password"
            onChange={e => setPass(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') handleLogin() }} />
        </div>

        <button className="btn primary block" onClick={handleLogin} disabled={loading} style={{ height: 40, marginTop: 6 }}>
          {loading ? <><RefreshCw size={14} className="spin" />Signing in…</> : 'Sign in'}
        </button>
      </div>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Status band — the one question an SME owner actually has
   ══════════════════════════════════════════════════════════════════════════ */

function StatusBand({ alerts, blockedIPs, logs, anyError, connected }: {
  alerts: Alert[], blockedIPs: BlockedIP[], logs: LogEntry[], anyError: boolean, connected: boolean
}) {
  const now = Date.now()

  const lastHour = useMemo(
    () => alerts.filter(a => now - parseTS(a.timestamp).getTime() < 3_600_000),
    [alerts, now],
  )

  const longestBlock = useMemo(() => {
    const secs = Date.now() / 1000
    const remaining = blockedIPs.map(b => (b.ttl ? b.ttl - secs : 0)).filter(v => v > 0)
    if (!remaining.length) return null
    const t = Math.max(...remaining)
    const h = Math.floor(t / 3600), m = Math.floor((t % 3600) / 60)
    return h > 0 ? `${h} h ${m} m` : `${m} m`
  }, [blockedIPs])

  let tone: 'calm' | 'active' | 'critical' = 'calm'
  let lead = 'All clear.'
  let highlight = 'No threats in the last hour.'
  let sub = 'Sentinel is watching every request to your portal. You’ll see a notification here the moment something looks wrong.'

  if (anyError) {
    tone = 'critical'
    lead = 'Sentinel can’t reach'
    highlight = 'the detection service.'
    sub = 'What you see below may be out of date. Blocking rules already in AWS WAF stay active regardless. Retrying automatically every 4 seconds.'
  } else if (lastHour.length > 0) {
    tone = 'active'
    lead = 'You’re covered.'
    highlight = `${lastHour.length} ${plural(lastHour.length, 'threat was', 'threats were')} handled in the last hour.`
    sub = blockedIPs.length > 0
      ? `Nothing needs your attention — Sentinel blocked ${plural(blockedIPs.length, 'the source', 'each source')} automatically. ${longestBlock ? `The longest block lifts in ${longestBlock}.` : 'Blocks lift on their own.'} Open Blocked IPs to unblock early.`
      : 'These were logged for monitoring only and did not meet the threshold for an automatic block.'
  }

  return (
    <section className={`status tone-${tone}`} aria-live="polite">
      <div className="spine" />
      <div className="body">
        <div className="eyebrow">Right now</div>
        <h1 className="verdict">{lead} <em>{highlight}</em></h1>
        <p className="subline">{sub}</p>
      </div>
      <RiskMeter logs={logs} connected={connected} />
    </section>
  )
}

/** The old gauge showed "63.4%" — a number with no unit and no instruction.
 *  Same maths, but reported as a band the user can act on. */
function RiskMeter({ logs, connected }: { logs: LogEntry[], connected: boolean }) {
  const currentScore = useMemo(() => {
    if (!logs || logs.length === 0) return 0.1
    const sorted = [...logs].sort((a, b) => b.timestamp.localeCompare(a.timestamp))
    return typeof sorted[0].score === 'number' ? sorted[0].score : 0.1
  }, [logs])

  let riskPercent = 0
  if (currentScore >= 0.1) { riskPercent = 0 }
  else if (currentScore >= 0.031) { riskPercent = ((0.1 - currentScore) / (0.1 - 0.031)) * 50 }
  else { riskPercent = 50 + ((0.031 - Math.max(-1.0, currentScore)) / (0.031 + 1.0)) * 50 }
  riskPercent = Math.min(Math.max(riskPercent, 0), 100)

  const band = riskPercent > 80 ? 'Act now' : riskPercent > 40 ? 'Watch' : 'Normal'
  const bandClass = riskPercent > 80 ? 'b-act' : riskPercent > 40 ? 'b-watch' : ''
  const note = riskPercent > 80
    ? 'The model is seeing traffic well outside its trained baseline. Check the alerts below.'
    : riskPercent > 40
      ? 'Busier than usual, but nothing the model can’t handle on its own.'
      : 'Traffic matches the trained baseline for this portal.'

  return (
    <div className="meter">
      <div className="meter-head">
        <span className={`meter-band ${bandClass}`}>{connected ? band : '—'}</span>
        <span className="meter-score">score {num(currentScore)}</span>
      </div>
      <div className="meter-track"
        role="meter" aria-valuenow={Math.round(riskPercent)} aria-valuemin={0} aria-valuemax={100}
        aria-label={`Current risk level: ${band}`}>
        <i /><i /><i />
        <span className="meter-needle" style={{ left: `${riskPercent}%` }} />
      </div>
      <div className="meter-scale"><span>Normal</span><span>Watch</span><span>Act now</span></div>
      <p className="meter-note">{note}</p>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Severity ledger
   ══════════════════════════════════════════════════════════════════════════ */

function SeverityLedger({ alerts }: { alerts: Alert[] }) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  alerts.forEach(a => { if (a.severity in counts) counts[a.severity as keyof typeof counts]++ })

  return (
    <div className="ledger">
      {(Object.entries(counts) as [keyof typeof counts, number][]).map(([sev, count]) => {
        const k = sevKey(sev)
        return (
          <div className={`tile ${count === 0 ? 'zero' : ''}`} key={sev}>
            <span className="bar" style={{ background: `var(--sev-${k})` }} />
            <div>
              <div className="n" style={{ color: count > 0 ? `var(--sev-${k}-fg)` : undefined }}>{count}</div>
              <div className="l">{titleCase(sev)}</div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Anomaly chart
   ══════════════════════════════════════════════════════════════════════════ */

function ChartTooltip({ active, payload, label }: any) {
  if (!active || !payload?.length) return null
  const p = payload[0].payload
  return (
    <div style={{
      background: 'var(--chart-tooltip-bg)', border: '1px solid var(--chart-tooltip-border)',
      borderRadius: 8, padding: '9px 11px', fontSize: 12.5, boxShadow: 'var(--shadow)',
    }}>
      <div style={{ color: 'var(--text-3)', marginBottom: 5, fontFamily: "'IBM Plex Mono', monospace" }}>
        {new Date(label).toLocaleTimeString('en-MY', { timeZone: MYT, hour12: false })}
      </div>
      <div style={{ fontWeight: 600, marginBottom: 3 }}>{p.type}</div>
      <div style={{ fontFamily: "'IBM Plex Mono', monospace", color: 'var(--text-2)' }}>
        {p.ip} · score {num(p.score)}
      </div>
    </div>
  )
}

function AnomalyChart({ alerts, onRunSim }: { alerts: Alert[], onRunSim?: () => void }) {
  const data = useMemo(() => (
    [...alerts]
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
      .slice(-40)
      // Raw score, not Math.abs(): the sign is the signal. Isolation Forest
      // returns negative for anomalies, so folding it positive threw away the
      // only thing the threshold line means.
      .map(a => ({
        time: parseTS(a.timestamp).getTime(),
        score: typeof a.score === 'number' ? a.score : 0,
        severity: a.severity,
        type: a.type,
        ip: a.source_ip,
      }))
  ), [alerts])

  if (data.length === 0) {
    return (
      <EmptyState
        icon={<Activity size={22} />}
        title="No detections yet"
        body="Sentinel hasn’t scored any traffic in this window. Run the attack simulator to generate sample traffic, or wait for live requests to arrive."
        action={onRunSim && <button className="btn" onClick={onRunSim}>Refresh now</button>}
      />
    )
  }

  return (
    <>
      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 6, right: 12, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id="scoreFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--brand)" stopOpacity={0.22} />
                <stop offset="100%" stopColor="var(--brand)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
            <XAxis dataKey="time" type="number" domain={['auto', 'auto']} scale="time"
              tickFormatter={formatClock} axisLine={false} tickLine={false}
              tick={{ fill: 'var(--chart-tick)', fontSize: 12, fontFamily: 'IBM Plex Mono' } as any} />
            <YAxis width={52} axisLine={false} tickLine={false}
              tickFormatter={(v: number) => num(v, 2)}
              tick={{ fill: 'var(--chart-tick)', fontSize: 12, fontFamily: 'IBM Plex Mono' } as any} />
            <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'var(--line-2)', strokeWidth: 1 }} />
            <ReferenceLine y={IF_THRESHOLD} stroke="var(--sev-critical)" strokeDasharray="5 4" strokeWidth={1.5} />
            <Area type="monotone" dataKey="score" stroke="var(--brand)" strokeWidth={2.2}
              fill="url(#scoreFill)" fillOpacity={1} dot={false} activeDot={{ r: 4 }} name="Anomaly score" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <div className="legend">
        <span><i style={{ background: 'var(--brand)' }} />Anomaly score</span>
        <span><i style={{ background: 'var(--sev-critical)' }} />Alert threshold ({num(IF_THRESHOLD, 2)})</span>
        <span style={{ color: 'var(--text-3)' }}>Lower is more anomalous</span>
      </div>
    </>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Alert list + threat report
   ══════════════════════════════════════════════════════════════════════════ */

function AlertList({ alerts, loading, onSelect }: {
  alerts: Alert[], loading: boolean, onSelect: (a: Alert) => void
}) {
  const sorted = useMemo(
    () => [...alerts].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')).slice(0, 50),
    [alerts],
  )

  if (loading && alerts.length === 0) return <Spinner label="Loading alerts…" />
  if (sorted.length === 0) {
    return (
      <EmptyState
        icon={<ShieldCheck size={22} />}
        title="No alerts"
        body="Nothing has crossed the detection threshold. This is the state you want."
      />
    )
  }

  return (
    <div>
      {sorted.map(a => {
        const isML = (a.method || '').toUpperCase().includes('ML') || (a.method || '').toLowerCase().includes('isolation')
        return (
          <button key={a.alert_id} className={`row r-${sevKey(a.severity)}`} onClick={() => onSelect(a)}>
            <span className="cell-sev"><SeverityPill severity={a.severity} /></span>
            <span className="cell-ip truncate"><IpCell ip={a.source_ip} geoAnomaly={a.geo_anomaly} /></span>
            <span className="grow">
              <span className="what">{a.type}</span>
              <div className="why truncate">{a.reason}</div>
            </span>
            <span className={`tag ${isML ? 'ml' : ''} hide-sm`}
              title={isML ? 'Detected by the Isolation Forest model' : 'Matched a deterministic rule'}>
              {isML ? 'ML' : 'Rule'}
            </span>
            <span className="when hide-sm">{typeof a.score === 'number' ? num(a.score, 3) : '—'}</span>
            <span className="when">{formatTime(a.timestamp)}</span>
          </button>
        )
      })}
    </div>
  )
}

function ThreatReport({ alert, onClose, onUnblock }: {
  alert: Alert, onClose: () => void, onUnblock: (ip: string) => void
}) {
  const closeRef = useRef<HTMLButtonElement>(null)
  const foreign = alert.geo_anomaly === true || (alert.geo_anomaly as any) === 'true'
  const isML = (alert.method || '').toUpperCase().includes('ML') || (alert.method || '').toLowerCase().includes('isolation')

  useEffect(() => {
    closeRef.current?.focus()
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="scrim" onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby="report-title">
        <div className="modal-head">
          <div className="grow">
            <div className="eyebrow" style={{ marginBottom: 6 }}>Threat report</div>
            <h3 id="report-title">{alert.type}</h3>
          </div>
          <SeverityPill severity={alert.severity} />
          <button ref={closeRef} className="btn ghost" onClick={onClose}
            aria-label="Close report" title="Close (Esc)" style={{ margin: '-4px -6px 0 2px' }}>
            <X size={16} />
          </button>
        </div>

        <dl className="facts">
          <div className="fact">
            <dt>Source address</dt>
            <dd>{alert.source_ip}</dd>
          </div>
          <div className="fact">
            <dt>Origin</dt>
            <dd>{foreign ? 'Outside Malaysia' : 'Malaysia'}</dd>
          </div>
          <div className="fact">
            <dt>Anomaly score</dt>
            <dd>{typeof alert.score === 'number' ? num(alert.score) : '—'}</dd>
          </div>
          <div className="fact">
            <dt>Detected by</dt>
            <dd>{isML ? 'Isolation Forest' : alert.method || 'Rule engine'}</dd>
          </div>
        </dl>

        <div className="modal-body">
          <h5>Why Sentinel flagged this</h5>
          <p className="quote">{alert.reason}</p>
          <h5 style={{ marginTop: 16 }}>What happened next</h5>
          <p className="modal-note">
            Detected at {formatTime(alert.timestamp)} (MYT). The source was added to the AWS WAF
            block list with a severity-proportional TTL and a Telegram notification was sent to the
            on-call admin. The block lifts automatically when the TTL expires.
          </p>
        </div>

        <div className="modal-foot">
          <button className="btn" onClick={onClose}>Close</button>
          <button className="btn primary" onClick={() => { onUnblock(alert.source_ip); onClose() }}>
            Unblock this address
          </button>
        </div>
      </div>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Log feed
   ══════════════════════════════════════════════════════════════════════════ */

const lvlClass = (lvl: string) => {
  const k = (lvl || '').toLowerCase()
  if (['critical', 'high', 'medium', 'audit', 'info', 'warn'].includes(k)) return `lvl-${k}`
  return 'lvl-info'
}

function LogFeed({ logs, loading, error, onRefresh }: {
  logs: LogEntry[], loading: boolean, error: boolean, onRefresh: () => void
}) {
  const [q, setQ] = useState('')

  const filtered = useMemo(() => {
    const needle = q.toLowerCase().trim()
    return [...logs]
      .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
      .filter(l => !needle || `${l.timestamp} ${l.level} ${l.source_ip} ${l.message} ${l.source || ''}`.toLowerCase().includes(needle))
  }, [logs, q])

  if (loading && logs.length === 0) return <Spinner label="Loading log stream…" />

  return (
    <div className="card">
      <div className="toolbar">
        <SearchBox value={q} onChange={setQ} placeholder={'Filter by address, level or message'} />
        <span className="count">{filtered.length} of {logs.length} records</span>
        <button className="btn sm ghost" onClick={onRefresh} title="Reconnect to the log stream">
          <RefreshCw size={13} />Reconnect
        </button>
      </div>

      {error && (
        <div className="form-error" style={{ margin: 16, marginBottom: 0 }} role="alert">
          <AlertTriangle size={15} aria-hidden="true" />
          <span>The log stream is unreachable. Records below may be stale.</span>
        </div>
      )}

      {filtered.length === 0 ? (
        q ? (
          <EmptyState
            icon={<Search size={22} />}
            title={`No records match “${q}”`}
            body={`Try a partial address like 175.136, a level like CRITICAL, or clear the filter to see all ${logs.length} records.`}
            action={<button className="btn" onClick={() => setQ('')}>Clear filter</button>}
          />
        ) : (
          <EmptyState
            icon={<Inbox size={22} />}
            title="No log records yet"
            body="Requests to the portal will appear here within a few seconds of arriving. Run the attack simulator to generate sample traffic."
          />
        )
      ) : (
        <div className="logs tall">
          {filtered.map((l, i) => (
            <div key={l.log_id || i}
              className={`log ${l.level === 'CRITICAL' ? 'is-critical' : l.level === 'AUDIT' ? 'is-audit' : ''}`}>
              <time>{formatTime(l.timestamp)}</time>
              <span className={`lvl ${lvlClass(l.level)}`}>{l.level}</span>
              <span className="ip" style={{ fontSize: 12.5 }}>{l.source_ip || '—'}</span>
              <span className="msg">{l.message}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Blocklist
   ══════════════════════════════════════════════════════════════════════════ */

function BlocklistPanel({ ips, logs, loading, error, onUnblock, onRefresh }: {
  ips: BlockedIP[], logs: LogEntry[], loading: boolean, error: boolean,
  onUnblock: (ip: string) => void, onRefresh: () => void
}) {
  const [q, setQ] = useState('')
  const [now, setNow] = useState(Date.now() / 1000)
  const [pending, setPending] = useState<string | null>(null)

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => clearInterval(timer)
  }, [])

  const sortedIPs = useMemo(() => {
    const needle = q.toLowerCase()
    return [...ips]
      .filter(i => !needle || `${i.ip} ${i.reason} ${i.severity}`.toLowerCase().includes(needle))
      .sort((a, b) => (b.blocked_at || '').localeCompare(a.blocked_at || ''))
  }, [ips, q])

  const auditLogs = useMemo(
    () => logs.filter(l => l.level === 'AUDIT')
      .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
      .slice(0, 50),
    [logs],
  )

  const expiringSoon = sortedIPs.filter(i => i.ttl && i.ttl - now > 0 && i.ttl - now < 600).length

  const handleUnblock = async (ip: string) => {
    setPending(ip)
    try { await onUnblock(ip) } finally { setPending(null) }
  }

  if (loading && ips.length === 0) return <Spinner label="Loading blocked addresses…" />

  return (
    <div className="stack">
      <div className="card">
        <div className="toolbar">
          <SearchBox value={q} onChange={setQ} placeholder="Filter blocked addresses by IP, reason or severity" />
          <span className="count">
            {sortedIPs.length} blocked{expiringSoon > 0 ? ` · ${expiringSoon} expiring soon` : ''}
          </span>
          <button className="btn sm ghost" onClick={onRefresh} title="Reconnect"><RefreshCw size={13} />Reconnect</button>
        </div>

        {error && (
          <div className="form-error" style={{ margin: 16, marginBottom: 0 }} role="alert">
            <AlertTriangle size={15} aria-hidden="true" />
            <span>Can’t read the block list right now. Existing WAF rules are still enforced.</span>
          </div>
        )}

        {sortedIPs.length === 0 ? (
          q ? (
            <EmptyState icon={<Search size={22} />} title={`Nothing matches “${q}”`}
              body="Try a partial address, or clear the filter to see every blocked address."
              action={<button className="btn" onClick={() => setQ('')}>Clear filter</button>} />
          ) : (
            <EmptyState icon={<ShieldCheck size={22} />} title="Nothing is blocked"
              body="No address is currently denied at the WAF. Sentinel adds entries here automatically when it detects a threat." />
          )
        ) : (
          <div>
            {sortedIPs.map((item, i) => {
              const timeLeft = item.ttl ? Math.max(0, item.ttl - now) : 0
              const h = Math.floor(timeLeft / 3600)
              const m = Math.floor((timeLeft % 3600) / 60)
              const s = Math.floor(timeLeft % 60)
              const label = h > 0 ? `${h}h ${m}m left` : m > 0 ? `${m}m ${s}s left` : `${s}s left`
              // TTL is severity-proportional; 4h is the longest band we issue.
              const pct = Math.min(100, (timeLeft / (4 * 3600)) * 100)

              return (
                <div key={`${item.ip}-${i}`} className={`block-row r-${sevKey(item.severity)}`}>
                  <span className="cell-sev"><SeverityPill severity={item.severity} /></span>
                  <span className="cell-ip"><IpCell ip={item.ip} geoAnomaly={item.geo_anomaly} /></span>
                  <span className="grow truncate block-reason">{item.reason}</span>
                  <span className="ttl">
                    <span className={`t ${timeLeft <= 0 ? 'expired' : ''}`}>
                      {timeLeft > 0 ? label : 'Expired — clearing'}
                    </span>
                    <span className="track"><span className="fill" style={{ width: `${pct}%` }} /></span>
                  </span>
                  <button className="btn sm" disabled={pending === item.ip}
                    onClick={() => handleUnblock(item.ip)}
                    aria-label={`Unblock ${item.ip}`}>
                    {pending === item.ip ? <RefreshCw size={12} className="spin" /> : null}
                    {pending === item.ip ? 'Unblocking' : 'Unblock'}
                  </button>
                </div>
              )
            })}
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <History size={15} color="var(--brand)" aria-hidden="true" />
          <span className="card-title">Remediation history</span>
          <span className="card-hint hide-sm">Every block and unblock, with who or what did it</span>
          <div className="spacer" />
          <span className="count">{auditLogs.length} events</span>
        </div>
        {auditLogs.length === 0 ? (
          <EmptyState icon={<History size={22} />} title="No remediation actions yet"
            body="Automatic blocks and manual unblocks are recorded here for audit." />
        ) : (
          <div className="logs short">
            {auditLogs.map((e, i) => (
              <div key={e.log_id || i} className="log is-audit">
                <time>{formatTime(e.timestamp)}</time>
                <span className="lvl lvl-audit">AUDIT</span>
                <span className="ip" style={{ fontSize: 12.5 }}>{e.source_ip || '—'}</span>
                <span className="msg">{e.message}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Critical notification
   ══════════════════════════════════════════════════════════════════════════ */

function CriticalToast({ alert, total, onView, onDismiss }: {
  alert: Alert, total: number, onView: () => void, onDismiss: () => void
}) {
  return (
    <div className="toast" role="alert" aria-live="assertive">
      <div className="toast-head">
        <AlertTriangle size={16} strokeWidth={2.2} aria-hidden="true" />
        Critical threat blocked
        {total > 1 && <span className="count" style={{ color: 'inherit' }}>{total} total</span>}
        <div className="spacer" />
        <button className="btn ghost sm" onClick={onDismiss}
          aria-label="Dismiss notification" title="Dismiss"
          style={{ color: 'inherit', margin: '-3px -5px' }}>
          <X size={14} />
        </button>
      </div>
      <div className="toast-body">
        <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 3 }}>{alert.type}</div>
        <IpCell ip={alert.source_ip} geoAnomaly={alert.geo_anomaly} />
        <p style={{ fontSize: 12.5, color: 'var(--text-2)', marginTop: 9 }}>
          Blocked automatically at the WAF. No action needed from you.
        </p>
        <div className="toast-actions">
          <button className="btn primary" onClick={onView}>View report</button>
          <button className="btn" onClick={onDismiss}>Dismiss</button>
        </div>
      </div>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Dashboard
   ══════════════════════════════════════════════════════════════════════════ */

function Dashboard({ onLogout, theme, toggleTheme }: { onLogout: () => void, theme: Theme, toggleTheme: () => void }) {
  const { data: alerts, status: alertsStatus, reset: resetAlerts } = usePolling<Alert[]>(fetchAlerts, [], { intervalMs: 4000 })
  const { data: blockedIPs, status: blockedStatus, reset: resetBlocked } = usePolling<BlockedIP[]>(fetchBlockedIPs, [], { intervalMs: 4000 })
  const { data: logs, status: logsStatus, reset: resetLogs } = usePolling<LogEntry[]>(fetchLogs, [], { intervalMs: 4000 })

  const connected = alertsStatus === 'open' && logsStatus === 'open' && blockedStatus === 'open'
  const anyError = alertsStatus === 'error' || logsStatus === 'error' || blockedStatus === 'error'
  const ipsError = blockedStatus === 'error'
  const logsError = logsStatus === 'error'

  const [tab, setTab] = useState<'overview' | 'logs' | 'blocklist'>('overview')
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)

  const handleUnblock = async (ip: string) => { await unblockIP(ip); resetBlocked() }
  const criticalAlerts = (alerts as Alert[]).filter(a => a.severity === 'CRITICAL')

  // Dismissal hides the NOTIFICATION only — never the alert itself. The alert
  // stays in the log and the IP stays blocked. Tracked per alert_id so a NEW
  // critical still surfaces, and held in component state (not persisted) so a
  // reload re-surfaces anything still outstanding. Silencing a critical
  // security alert permanently with one click would be an anti-pattern.
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set())
  const activeCritical = criticalAlerts.find(a => !dismissedIds.has(a.alert_id))
  const dismissCritical = useCallback((id: string) => {
    setDismissedIds(prev => { const next = new Set(prev); next.add(id); return next })
  }, [])

  const TABS = [
    { id: 'overview' as const, label: 'Overview', icon: Activity },
    { id: 'logs' as const, label: 'Log stream', icon: Terminal },
    { id: 'blocklist' as const, label: 'Blocked IPs', icon: Ban, badge: (blockedIPs as BlockedIP[]).length },
  ]

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <div className="mark"><Shield size={15} strokeWidth={2.2} aria-hidden="true" /></div>
          <div className="wordmark">ACS Sentinel</div>
          <div className="spacer" />

          {criticalAlerts.length > 0 && dismissedIds.size > 0 && (
            <button className="btn sm ghost" onClick={() => setDismissedIds(new Set())}
              title={`Show ${criticalAlerts.length} critical ${plural(criticalAlerts.length, 'alert', 'alerts')}`}
              style={{ color: 'var(--sev-critical-fg)' }}>
              <Bell size={14} />{criticalAlerts.length}
            </button>
          )}

          <div className={`chip hide-sm ${connected ? 'is-live' : anyError ? 'is-error' : 'is-wait'}`}>
            <span className="dot" />
            {connected ? <><Wifi size={13} aria-hidden="true" />Live</>
              : anyError ? <><WifiOff size={13} aria-hidden="true" />Reconnecting</>
                : <><RefreshCw size={13} className="spin" aria-hidden="true" />Connecting</>}
          </div>

          <ThemeButton theme={theme} toggleTheme={toggleTheme} />
          <button className="btn ghost" onClick={onLogout} title="Sign out" aria-label="Sign out">
            <LogOut size={16} />
          </button>
        </div>
      </header>

      <div className="app">
        <StatusBand alerts={alerts as Alert[]} blockedIPs={blockedIPs as BlockedIP[]}
          logs={logs as LogEntry[]} anyError={anyError} connected={connected} />

        <SeverityLedger alerts={alerts as Alert[]} />

        <div className="tabs" role="tablist" aria-label="Dashboard sections">
          {TABS.map(t => (
            <button key={t.id} className="tab" role="tab" aria-selected={tab === t.id}
              onClick={() => setTab(t.id)}>
              <t.icon size={15} aria-hidden="true" />
              {t.label}
              {!!t.badge && t.badge > 0 && <span className="badge">{t.badge}</span>}
            </button>
          ))}
        </div>

        {tab === 'overview' && (
          <div className="stack">
            <div className="card">
              <div className="card-head">
                <span className="card-title">Anomaly score over time</span>
                <span className="card-hint hide-sm">Last {Math.min(40, (alerts as Alert[]).length)} detections · Malaysia time</span>
                <div className="spacer" />
                <button className="btn sm ghost" onClick={resetAlerts} title="Refresh now">
                  <RefreshCw size={13} />Refresh
                </button>
              </div>
              <AnomalyChart alerts={alerts as Alert[]} onRunSim={resetAlerts} />
            </div>

            <div className="card">
              <div className="card-head">
                <span className="card-title">Recent alerts</span>
                <span className="card-hint">Select a row for the full report</span>
              </div>
              <AlertList alerts={alerts as Alert[]} loading={alertsStatus === 'connecting'} onSelect={setSelectedAlert} />
            </div>
          </div>
        )}

        {tab === 'logs' && (
          <LogFeed logs={logs as LogEntry[]} loading={logsStatus === 'connecting'} error={logsError} onRefresh={resetLogs} />
        )}

        {tab === 'blocklist' && (
          <BlocklistPanel ips={blockedIPs as BlockedIP[]} logs={logs as LogEntry[]}
            loading={blockedStatus === 'connecting'} error={ipsError}
            onUnblock={handleUnblock} onRefresh={resetBlocked} />
        )}

        <footer className="foot">
          <ShieldCheck size={13} color="var(--ok)" aria-hidden="true" />
          Automatic blocking is on
          <div className="spacer" />
          <span className="mono">MYT (UTC+8)</span>
        </footer>
      </div>

      {activeCritical && (
        <CriticalToast alert={activeCritical} total={criticalAlerts.length}
          onView={() => { setSelectedAlert(activeCritical); dismissCritical(activeCritical.alert_id) }}
          onDismiss={() => dismissCritical(activeCritical.alert_id)} />
      )}

      {selectedAlert && (
        <ThreatReport alert={selectedAlert} onClose={() => setSelectedAlert(null)} onUnblock={handleUnblock} />
      )}
    </>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Root
   ══════════════════════════════════════════════════════════════════════════ */

export default function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const [theme, setTheme] = useState<Theme>(() => {
    try { return (localStorage.getItem('acs-theme') as Theme) || 'dark' } catch { return 'dark' }
  })
  useEffect(() => { applyTheme(theme); try { localStorage.setItem('acs-theme', theme) } catch { } }, [theme])
  const toggleTheme = useCallback(() => setTheme(t => (t === 'dark' ? 'light' : 'dark')), [])

  if (!authenticated) return <LoginScreen onLogin={() => setAuthenticated(true)} theme={theme} toggleTheme={toggleTheme} />
  return <Dashboard onLogout={() => { signOut(); setAuthenticated(false) }} theme={theme} toggleTheme={toggleTheme} />
}
