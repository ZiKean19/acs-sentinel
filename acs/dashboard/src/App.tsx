import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import {
  Shield, ShieldCheck, Activity, Ban, Bell, Terminal, LogOut, Sun, Moon,
  RefreshCw, X, Search, AlertTriangle, AlertCircle, MinusCircle,
  CheckCircle2, History, Wifi, WifiOff, Inbox, Download, Users, UserPlus, Trash2,
  ChevronsLeft, ExternalLink, ChevronDown,
} from 'lucide-react'
import {
  ComposedChart, Area, Scatter, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine, CartesianGrid,
} from 'recharts'
import { fetchAlerts, fetchBlockedIPs, fetchLogs, fetchLogPage, unblockIP } from './api/client'
import { listUsers, inviteUser, removeUser, setUserRole } from './api/client'
import type { Alert, BlockedIP, LogEntry, ManagedUser, ManagedRole, DomainAllow } from './api/client'
import { usePolling } from './hooks/usePolling'
import { signIn, signOut, signInWithGoogle, completeOAuthRedirect, isAuthenticated, getRole, getEmail, type Role } from './api/auth'

export type { Alert, BlockedIP, LogEntry }

/* ══════════════════════════════════════════════════════════════════════════
   Constants & helpers
   ══════════════════════════════════════════════════════════════════════════ */

const MYT = 'Asia/Kuala_Lumpur'

/** Isolation Forest alert threshold — must mirror IF_THRESHOLD in the
 *  Detection Lambda. Scores below this are treated as anomalous. */
const IF_THRESHOLD = -0.02

/* ── Risk gauge scale ────────────────────────────────────────────────────────
 *  Both detection paths write the same `score` field on scales that do not
 *  match: the Isolation Forest decision function lands roughly in +0.15…−0.25,
 *  while the rule engine emits fixed −0.3 / −0.6 / −0.8 / −1.0.
 *
 *  The old anchors (50% at 0.031, 100% at −1.0) sized the sweep for the rule
 *  engine, so the entire ML range was squeezed into the lower half — an ML HIGH
 *  landed at "Watch" while a rule MEDIUM pegged "Act now". Anchoring 50% at the
 *  alert threshold and 100% at −0.10 spreads the ML range across the full sweep
 *  and lets every rule score peg at the top, which is what a rule hit means.  */
const SCORE_NORMAL = 0.1     // ≥ this →   0%  (comfortably inside the baseline)
const SCORE_SEVERE = -0.10   // ≤ this → 100%  (ML saturation; all rule scores)

/** Band cut-points, in percent of the risk scale (chart Y axis and the status
 *  dot agree on these). 50% is IF_THRESHOLD itself, so anything below it never
 *  tripped a detector; 75% is the midpoint of the anomalous half (−0.06). */
const BAND_WATCH = 50
const BAND_ACT = 75

/** How recent a reading must be to speak in the present tense. Applies to the
 *  heartbeat AND to the risk band — see the note at `dotClass`. */
const FRESH_MS = 90_000

const clamp = (n: number, lo: number, hi: number) => Math.min(Math.max(n, lo), hi)

/** Reads an anomaly score off the wire, whatever shape it arrives in.
 *
 *  DynamoDB stores numbers as Decimal, which `json.dumps` cannot serialise. The
 *  usual Lambda escape hatch — `json.dumps(items, default=str)` — turns
 *  Decimal('-0.0312') into the STRING "-0.0312". `typeof x === 'number'` then
 *  rejects every score in the feed while `level`, `message` and `source_ip`
 *  keep rendering fine, because those were strings all along. The gauge's old
 *  `return 0.1` fallback quietly papered over exactly this: a wire full of
 *  strings still drew a confident "Normal".
 *
 *  Coerce here rather than trust the producer. Returns null for genuinely
 *  absent or unparseable values — never a stand-in number. */
function toScore(v: unknown): number | null {
  if (typeof v === 'number') return Number.isFinite(v) ? v : null
  if (typeof v === 'string') {
    const t = v.trim()
    if (!t) return null
    const n = Number(t)
    return Number.isFinite(n) ? n : null
  }
  // Raw DynamoDB AttributeValue, if the Lambda used the client API and skipped
  // the TypeDeserializer: { "N": "-0.0312" }
  if (v && typeof v === 'object' && typeof (v as any).N === 'string') return toScore((v as any).N)
  return null
}

/** Field names the score might arrive under. `score` is what the Detection
 *  Lambda is meant to write; the aliases cost one property lookup each and
 *  cover the usual drift between a Lambda's field name and the dashboard's
 *  expectation. Order matters — first hit wins. */
const SCORE_KEYS = ['score', 'anomaly_score', 'ml_score', 'if_score', 'risk_score'] as const

function pickScore(entry: unknown): number | null {
  if (!entry || typeof entry !== 'object') return null
  for (const k of SCORE_KEYS) {
    const v = toScore((entry as Record<string, unknown>)[k])
    if (v !== null) return v
  }
  return null
}

/** Works out WHY a feed yielded no scores, so the empty state can name the
 *  fault instead of leaving someone to diff Lambda source against a blank
 *  chart. Two faults look identical from the outside and have nothing to do
 *  with each other: a field that was never written, and a field that was
 *  written but can't be read. */
function diagnoseScores(logs: LogEntry[]): { title: string, body: string } {
  const sample = (logs[0] ?? {}) as unknown as Record<string, unknown>
  const fields = Object.keys(sample)
  // Anything score-ish, under any name, anywhere in the sample.
  const scoreLike = fields.filter(f => /score/i.test(f))

  if (scoreLike.length === 0) {
    return {
      title: 'These log entries carry no anomaly score',
      body: `Sentinel received ${logs.length} ${plural(logs.length, 'entry', 'entries')}, and none has a score field at all. The Detection Lambda is not writing one to the log-stream table — the alerts table is scored, the log stream is not. Fields present: ${fields.join(', ') || '(none)'}.`,
    }
  }
  const k = scoreLike[0]
  const raw = sample[k]
  return {
    title: 'The score field is present but unreadable',
    body: `Found "${k}" on the newest entry, but its value (${JSON.stringify(raw)}, type ${raw === null ? 'null' : typeof raw}) will not parse as a number. Check how the Dashboard Lambda serialises this field. Fields present: ${fields.join(', ')}.`,
  }
}

/* ── Chart frame ─────────────────────────────────────────────────────────────
 *  The chart plots RISK (riskPercentFor), not the raw score, so it shares one
 *  scale with the gauge: 50% is the alert threshold on both, and danger reads
 *  upward — the direction every monitoring convention trains people to scan
 *  for. Raw scores made spikes point down, which reads as "activity dropped".
 *  The true score still travels with each point and shows in the tooltip.
 *
 *  The Y domain is padded past [0, 100] on both ends so a quiet baseline draws
 *  just above the axis instead of on it, and off-scale rule scores (risk 100)
 *  sit just under the top edge instead of against it. The pad is visual only:
 *  no data value can enter it. */
const RISK_Y_PAD = 4
const RISK_TICKS = [0, 25, 50, 75, 100]

/** Selectable chart windows. Ticks show seconds only where a tick interval is
 *  short enough for seconds to differ between neighbouring ticks. */
// Windows stop at 3 days because that is as far back as the data goes: alerts
// carry a severity-proportional TTL topping out at 72 h (CRITICAL), so a longer
// span would query a range DynamoDB has already expired and render an empty
// stretch. Four steps rather than six — each is a meaningful jump.
const CHART_WINDOWS = [
  { label: 'Last 15 min', ms: 15 * 60_000, secTicks: true, days: false },
  { label: 'Last hour', ms: 60 * 60_000, secTicks: false, days: false },
  { label: 'Last 24 hours', ms: 24 * 3_600_000, secTicks: false, days: false },
  { label: 'Last 3 days', ms: 3 * 86_400_000, secTicks: false, days: true },
]

/** A ticking clock for "x seconds ago" copy and draining TTL bars. One shared
 *  hook so every live element in the app agrees on what "now" is. */
function useNowMs(stepMs = 1000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), stepMs)
    return () => clearInterval(t)
  }, [stepMs])
  return now
}

const agoLabel = (ms: number) => {
  const sec = Math.max(0, Math.round(ms / 1000))
  return sec < 60 ? `${sec}s` : `${Math.floor(sec / 60)}m ${sec % 60}s`
}

/** Maps a raw anomaly score onto the 0–100 sweep. Piecewise-linear with the
 *  knee at IF_THRESHOLD so both halves stay legible at their own resolution. */
function riskPercentFor(score: number): number {
  const pct = score >= IF_THRESHOLD
    ? ((SCORE_NORMAL - score) / (SCORE_NORMAL - IF_THRESHOLD)) * 50
    : 50 + ((IF_THRESHOLD - score) / (IF_THRESHOLD - SCORE_SEVERE)) * 50
  return clamp(pct, 0, 100)
}

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
function formatClockSec(t: number): string {
  return new Date(t).toLocaleTimeString('en-MY', { timeZone: MYT, hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}
function formatDay(t: number): string {
  return new Date(t).toLocaleDateString('en-MY', { timeZone: MYT, month: 'short', day: 'numeric' })
}
/** Minus sign (U+2212) rather than hyphen: aligns with tabular figures. */
const num = (n: number, dp = 4) => n.toFixed(dp).replace('-', '−')
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many)

type Theme = 'dark' | 'light'
function applyTheme(theme: Theme) { document.documentElement.setAttribute('data-theme', theme) }

type SevKey = 'critical' | 'high' | 'medium' | 'low' | 'unknown'
/** Ordered worst-first — the legend reads the same way the ledger tiles do. */
const SEV_LEVELS = ['critical', 'high', 'medium', 'low'] as const
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

function IpCell({ ip, geoAnomaly }: { ip: string, geoAnomaly?: boolean | string | number }) {
  // The API returns geo_anomaly as 0/1 (DynamoDB numeric). Comparing a number
  // against `true`/`'true'` is always false, so every IP rendered as Malaysian.
  // Coerce instead of strict-comparing, and accept all three shapes.
  const foreign = Number(geoAnomaly) === 1 || geoAnomaly === true || geoAnomaly === 'true'
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

/* ── Export ──────────────────────────────────────────────────────────────────
 *  Every export goes through the SAME rows the table or chart is currently
 *  showing — window, traffic filter and search included — so what you see is
 *  exactly what you get. The row count on the button states that contract
 *  up front instead of leaving it to be discovered after the download.
 */

/** A column knows its header and how to read a value off a row. Exports are
 *  defined next to the component that owns the data, not in a central map. */
type Col<T> = { label: string, value: (row: T) => string | number }

function tableOf<T>(rows: T[], columns: Col<T>[]) {
  const header = columns.map(c => c.label)
  const data = rows.map(r => columns.map(c => {
    const v = c.value(r)
    return v === undefined || v === null ? '' : v
  }))
  return { header, data }
}

function csvOf(header: string[], data: (string | number)[][]): string {
  const esc = (v: string | number) => {
    const s = String(v)
    return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  // BOM so Excel opens UTF-8 CSVs without mangling anything non-ASCII.
  return '\uFEFF' + [header, ...data].map(row => row.map(esc).join(',')).join('\r\n')
}

function downloadBlob(filename: string, blob: Blob) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url; a.download = filename
  document.body.appendChild(a); a.click(); a.remove()
  URL.revokeObjectURL(url)
}

const exportStamp = () => {
  const d = new Date()
  const p = (n: number) => n.toString().padStart(2, '0')
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`
}

async function exportRows<T>(kind: 'csv' | 'xlsx', name: string, rows: T[], columns: Col<T>[]) {
  const { header, data } = tableOf(rows, columns)
  const filename = `acs-sentinel-${name}-${exportStamp()}.${kind}`
  if (kind === 'csv') {
    downloadBlob(filename, new Blob([csvOf(header, data)], { type: 'text/csv;charset=utf-8' }))
    return
  }
  // SheetJS is ~400 KB, so it loads on first use rather than riding along in
  // the main bundle for people who never export.
  const XLSX = await import('xlsx')
  const ws = XLSX.utils.aoa_to_sheet([header, ...data])
  const wb = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(wb, ws, 'ACS Sentinel')
  XLSX.writeFile(wb, filename)
}

function ExportMenu<T>({ name, rows, columns }: { name: string, rows: T[], columns: Col<T>[] }) {
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState<'csv' | 'xlsx' | null>(null)
  const wrapRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(e.target as Node)) setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey) }
  }, [open])

  const run = async (kind: 'csv' | 'xlsx') => {
    setBusy(kind)
    try { await exportRows(kind, name, rows, columns) }
    catch (e) { console.error('Export failed:', e) }
    finally { setBusy(null); setOpen(false) }
  }

  const none = rows.length === 0
  return (
    <div className="export" ref={wrapRef}>
      <button className="btn sm ghost" onClick={() => setOpen(o => !o)} disabled={none || busy !== null}
        aria-haspopup="menu" aria-expanded={open}
        title={none ? 'Nothing matches the current filter, so there is nothing to export'
          : `Export the ${rows.length} ${plural(rows.length, 'row', 'rows')} currently in view`}>
        {busy ? <RefreshCw size={13} className="spin" /> : <Download size={13} />}
        Export{!none && <span className="count" style={{ color: 'inherit' }}>{rows.length}</span>}
      </button>
      {open && (
        <div className="menu" role="menu" aria-label="Export format">
          <button role="menuitem" onClick={() => run('csv')}>
            <span>CSV</span><small>Opens anywhere, plain text</small>
          </button>
          <button role="menuitem" onClick={() => run('xlsx')}>
            <span>Excel (.xlsx)</span><small>Formatted workbook</small>
          </button>
        </div>
      )}
    </div>
  )
}

/* ── Segmented filter ────────────────────────────────────────────────────────
 *  One control, all options visible at once with their counts — the reader
 *  sees what each choice yields BEFORE clicking, and the active option is
 *  marked by state (aria-pressed) as well as colour. */
function Segmented<K extends string>({ options, value, onChange, label }: {
  options: { key: K, label: string, count?: number }[], value: K, onChange: (k: K) => void, label: string
}) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map(o => (
        <button key={o.key} aria-pressed={value === o.key} onClick={() => onChange(o.key)}>
          {o.label}
          {o.count !== undefined && <span className="seg-n">{o.count}</span>}
        </button>
      ))}
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Login
   ══════════════════════════════════════════════════════════════════════════ */

function LoginScreen({ onLogin, theme, toggleTheme, initialError }: { onLogin: () => void, theme: Theme, toggleTheme: () => void, initialError?: string }) {
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [err, setErr] = useState(initialError ?? '')
  const [loading, setLoading] = useState(false)
  const [googleLoading, setGoogleLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)

  // Navigates away on success, so there is no resolve path to handle — only
  // the failure case ever returns here.
  const handleGoogle = async () => {
    setErr(''); setGoogleLoading(true)
    try { await signInWithGoogle() }
    catch (e: any) { setErr(e?.message || 'Could not start Google sign-in.'); setGoogleLoading(false) }
  }

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
        <div className="login-mark" style={{ margin: '0 auto' }}><Shield size={22} strokeWidth={2.2} /></div>
        <h1 style={{ textAlign: 'center' }}>Sign in to ACS Sentinel</h1>

        {err && (
          <div className="form-error" role="alert">
            <AlertTriangle size={15} aria-hidden="true" />
            <span>{err}</span>
          </div>
        )}

        {/* Primary path. Federation proves identity; the PreSignUp allowlist
            decides authorisation, so this button is not a way in by itself. */}
        <button onClick={handleGoogle} disabled={googleLoading || loading}
          style={{
            width: '100%', height: 40, display: 'flex', alignItems: 'center', justifyContent: 'center',
            gap: 10, marginTop: 4, background: 'var(--bg-card)', border: '1px solid var(--border-bright)',
            color: 'var(--text-primary)', borderRadius: 6, fontSize: 14,
            cursor: googleLoading || loading ? 'default' : 'pointer',
            opacity: googleLoading || loading ? 0.6 : 1,
          }}>
          <svg width="17" height="17" viewBox="0 0 48 48" aria-hidden="true">
            <path fill="#4285F4" d="M45.1 24.5c0-1.6-.1-3.1-.4-4.5H24v8.5h11.8c-.5 2.7-2 5-4.4 6.6v5.5h7.1c4.1-3.8 6.6-9.4 6.6-16.1z" />
            <path fill="#34A853" d="M24 46c5.9 0 10.9-2 14.5-5.4l-7.1-5.5c-2 1.3-4.5 2.1-7.4 2.1-5.7 0-10.5-3.8-12.2-9H4.5v5.7C8.1 41.1 15.5 46 24 46z" />
            <path fill="#FBBC05" d="M11.8 28.2c-.4-1.3-.7-2.7-.7-4.2s.3-2.9.7-4.2v-5.7H4.5C3 17 2 20.4 2 24s1 7 2.5 9.9l7.3-5.7z" />
            <path fill="#EA4335" d="M24 10.8c3.2 0 6.1 1.1 8.4 3.3l6.3-6.3C34.9 4.2 29.9 2 24 2 15.5 2 8.1 6.9 4.5 14.1l7.3 5.7c1.7-5.2 6.5-9 12.2-9z" />
          </svg>
          {googleLoading ? 'Redirecting to Google…' : 'Continue with Google'}
        </button>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '16px 0 4px' }}>
          <span style={{ flex: 1, height: 1, background: 'var(--border)' }} />
          <span style={{ fontSize: 12, color: 'var(--text-dim)' }}>or</span>
          <span style={{ flex: 1, height: 1, background: 'var(--border)' }} />
        </div>

        {/* Break-glass. Kept deliberately secondary and progressively disclosed:
            one primary action when the screen loads, and the password path only
            appears for the operator who is looking for it. */}
        {!showPassword ? (
          <button onClick={() => setShowPassword(true)} aria-expanded={false}
            style={{
              width: '100%', height: 36, background: 'transparent', border: 'none',
              color: 'var(--text-dim)', fontSize: 13, cursor: 'pointer', textDecoration: 'underline',
            }}>
            Sign in with a password
          </button>
        ) : (
          <>
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

            <p style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 10, textAlign: 'center', lineHeight: 1.5 }}>
              Emergency access. Use Google unless the identity provider is unavailable.
            </p>
          </>
        )}
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
    lead = 'Handled automatically.'
    highlight = `${lastHour.length} ${plural(lastHour.length, 'threat was', 'threats were')} blocked in the last hour.`
    sub = blockedIPs.length > 0
      ? `No action needed — Sentinel blocked ${plural(blockedIPs.length, 'the source', 'each source')} at the WAF. ${longestBlock ? `Blocks lift on their own; the longest has ${longestBlock} left.` : 'Blocks lift on their own.'} If one was a legitimate visitor, you can release it under Blocked IPs.`
      : 'No source is blocked right now — earlier blocks have already lifted, or these were logged for monitoring only.'
  }

  // ── Heartbeat (absorbed from the retired RiskMeter panel) ────────────────
  // The gauge duplicated what the risk chart now shows on the same 0–100
  // scale, so the 290px panel earned its width twice over — once in pixels,
  // once in redundancy. What was NOT redundant survives here: the pulsing
  // freshness dot and the latest score, folded into the band itself.
  // Freshness comes from ANY log line, not just scored ones. The heartbeat's
  // question is "is traffic still reaching Sentinel", and an unscored request
  // answers that just as well as a scored one. Keying this to scored logs meant
  // a stream delivering 100 entries a minute reported "nothing scored yet" with
  // a dead grey dot — the strip called the pipeline dead while watching it run.
  const lastSeen = useMemo<number | null>(() => {
    const ts = logs.map(l => parseTS(l.timestamp).getTime()).filter(t => Number.isFinite(t))
    return ts.length ? Math.max(...ts) : null
  }, [logs])

  // The score chip is a different claim — "here is the newest reading" — and
  // only the log stream can back it. Alerts are scored too, but the newest
  // alert may be hours old; presenting that as current would be a lie.
  const latest = useMemo<{ score: number, ts: number } | null>(() => {
    const scored = logs
      .map(l => ({ score: pickScore(l), ts: parseTS(l.timestamp).getTime() }))
      .filter(r => r.score !== null && Number.isFinite(r.ts))
      .sort((a, b) => b.ts - a.ts)
    const l = scored[0]
    return l ? { score: l.score as number, ts: l.ts } : null
  }, [logs])
  const score = latest?.score ?? null

  const nowMs = useNowMs(1000)
  const sinceLast = lastSeen !== null ? nowMs - lastSeen : null
  // A "live" claim needs recent evidence. Past ~90s of silence the pulse stops
  // and the copy says quiet, so the dot can't vouch for a dead pipeline.
  const isFresh = sinceLast !== null && sinceLast < FRESH_MS

  // The dot now agrees with the verdict beside it: amber when the last-hour
  // verdict is "threats handled", grey when we can't vouch (disconnected, or
  // the stream has gone quiet), green when calm and fresh. Colouring it off a
  // stale max score was what left an orange verdict sitting next to a grey dot.
  const dotClass = anyError || !connected ? 'idle'
    : tone === 'active' ? 'b-watch'
      : !isFresh ? 'idle'
        : ''

  // In the calm state the static explainer gives way to live evidence — the
  // sentence that ages in real time is what makes the strip read as working.
  if (tone === 'calm' && connected) {
    sub = lastSeen === null
      ? 'No requests yet — this strip wakes up with the first one to reach your portal.'
      : !isFresh
        ? `Stream quiet for ${agoLabel(sinceLast ?? 0)} — no new requests.`
        : score !== null
          ? `Last request scored ${agoLabel(sinceLast!)} ago — inside the baseline.`
          : `Last request seen ${agoLabel(sinceLast!)} ago. Sentinel is watching every request.`
  }

  return (
    <section className={`status tone-${tone}`} aria-live="polite">
      <div className="spine" />
      <span className={`live-dot ${dotClass}`} aria-hidden="true" />
      <div className="body">
        <h1 className="verdict">{lead} <em>{highlight}</em></h1>
        <p className="subline">{sub}</p>
      </div>
    </section>
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
      <div style={{ fontWeight: 600, marginBottom: 3, maxWidth: 260 }}>{p.label}</div>
      <div style={{ fontFamily: "'IBM Plex Mono', monospace", color: 'var(--text-2)' }}>
        {p.ip} · score {num(p.raw)} · risk {Math.round(p.risk)}%
      </div>
      {/* Rule-engine scores live past the 100% anchor; the point is drawn at
          the top, so say so rather than let the reader think −1.0 ≈ −0.10. */}
      {p.raw < SCORE_SEVERE && (
        <div style={{ fontSize: 11.5, color: 'var(--text-3)', marginTop: 4 }}>
          Off the scale — drawn at 100%
        </div>
      )}
    </div>
  )
}

/** Only points that crossed the threshold carry a dot. Dotting every sample
 *  turns the series into a string of beads and buries the breaches; dotting none
 *  (the old `dot={false}`) meant a one-sample spike — which is what a real
 *  detection usually looks like — could pass for a kink in the line. */
type ChartPoint = { time: number, raw: number, risk: number, label: string, ip: string, severity?: string }

/** Detections plot as discrete dots coloured by severity — never joined by a
 *  line. Alerts are sparse and irregular; a stroke between one at 05:54 and the
 *  next at 14:12 would assert eight hours of risk nobody measured. The gap IS
 *  the information. */
function SeverityDot({ cx, cy, payload }: any) {
  if (cx == null || cy == null || !payload) return null
  return (
    <circle cx={cx} cy={cy} r={4.5} fill={`var(--sev-${sevKey(payload.severity)})`}
      stroke="var(--panel)" strokeWidth={1.5} />
  )
}

function BreachDot({ cx, cy, payload }: any) {
  if (cx == null || cy == null || !payload || payload.raw >= IF_THRESHOLD) return null
  // Colour by severity so a breach reads the same here as in the Anomalies tab
  // and in the severity ledger — red no longer doubles as both "anomaly" and
  // "critical". Falls back to the shared unknown grey when severity is absent.
  return <circle cx={cx} cy={cy} r={4} fill={`var(--sev-${sevKey(payload.severity)})`}
    stroke="var(--panel)" strokeWidth={2} />
}

/** Plots the LOG STREAM, not the alerts table. Every row in `alerts` has already
 *  crossed IF_THRESHOLD by definition, so charting it drew a series that lives
 *  entirely below the threshold line — the line was never crossed, every point
 *  was a "breach", and the gaps between detections were joined by a stroke that
 *  implied traffic nobody had measured. A threshold only means something against
 *  the baseline it cuts through, and the baseline is the normal requests. */
/** Plots the LOG STREAM when it carries scores: every scored request, so the
 *  threshold line has a baseline to cut through. That is the intended chart.
 *
 *  When the stream carries no scores it falls back to the alerts table, which is
 *  always scored — but presents it honestly as what it is. Every alert is past
 *  the threshold by definition, so there is no baseline and no trend to draw;
 *  joining them with a line would invent traffic between detections. Detections
 *  mode therefore plots dots only, and says so in the legend. The moment the
 *  Detection Lambda starts writing `score` to log-stream, this flips itself back
 *  to the full baseline chart with no code change. */
type TrafficFilter = 'all' | 'normal' | 'anomaly'

function AnomalyChart({ logs, alerts, onRunSim }: { logs: LogEntry[], alerts: Alert[], onRunSim?: () => void }) {
  const [winIdx, setWinIdx] = useState(1) // default: last hour
  const [traffic, setTraffic] = useState<TrafficFilter>('all')
  const win = CHART_WINDOWS[winIdx]

  // Multi-day windows need more than the live poll's ~300 lines. Pull a bounded
  // slice of history for the selected span (server-side range via `from` once
  // the Lambda supports it; otherwise it pages back and stops at the cap here).
  // Sub-day windows are fully covered by the live stream, so we skip the fetch.
  const [history, setHistory] = useState<LogEntry[]>([])
  useEffect(() => {
    if (!win.days) { setHistory([]); return }
    let cancelled = false
    ;(async () => {
      try {
        const from = new Date(Date.now() - win.ms).toISOString()
        let items: LogEntry[] = []
        let c: string | null | undefined = undefined
        for (let g = 0; g < 8 && items.length < 2000; g++) {
          const page = await fetchLogPage({ from, cursor: c ?? undefined, limit: 400 })
          if (cancelled) return
          items = items.concat(page.items)
          c = page.cursor
          if (!c) break
        }
        if (!cancelled) setHistory(items)
      } catch { if (!cancelled) setHistory([]) }
    })()
    return () => { cancelled = true }
  }, [win.days, win.ms])

  const { data, counts, domainX, scoredCount, mode } = useMemo(() => {
    const end = Date.now()
    const start = end - win.ms

    const collect = (
      src: Array<Record<string, any>>,
      label: (r: any) => string,
      severity?: (r: any) => string,
    ): ChartPoint[] => {
      const out: ChartPoint[] = []
      for (const r of src) {
        // AUDIT rows (sign-ins and the like) never went through the model, so a
        // missing score there is expected — it is not a parse failure.
        const raw = pickScore(r)
        const time = parseTS(r.timestamp).getTime()
        if (raw === null || !Number.isFinite(time)) continue
        // `raw` is what actually happened; `risk` is what gets drawn. The sign
        // of the raw score is the signal — riskPercentFor keeps it (50% IS the
        // threshold) while giving the plot the danger-up orientation.
        out.push({ time, raw, risk: riskPercentFor(raw), label: label(r), ip: r.source_ip, severity: severity?.(r) })
      }
      return out
    }

    // The Detection Lambda writes the alert severity into `level` for
    // anomalous rows (INFO otherwise), so anomaly dots can colour by severity
    // instead of falling back to the grey "unknown".
    const SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
    const srcLogs = history.length
      ? [...new Map([...history, ...logs].map(l => [l.log_id || `${l.timestamp}-${l.message}`, l])).values()]
      : logs
    const fromLogs = collect(srcLogs, l => l.message, l => (SEVS.includes(l.level) ? l.level : undefined as any))
    const usingLogs = fromLogs.length > 0
    const rows = usingLogs
      ? fromLogs
      : collect(alerts, a => a.type, a => a.severity)

    const inWindow = rows
      .filter(r => r.time >= start && r.time <= end)
      .sort((a, b) => a.time - b.time)
      .slice(-240)

    // A point is anomalous iff its raw score crossed the detector's own
    // threshold — the same test the Detection Lambda applies, so the filter
    // never disagrees with the alert list about what counts as an anomaly.
    const isAnomaly = (p: ChartPoint) => p.raw < IF_THRESHOLD
    const counted = {
      all: inWindow.length,
      normal: inWindow.filter(p => !isAnomaly(p)).length,
      anomaly: inWindow.filter(isAnomaly).length,
    }
    const shown = traffic === 'all' ? inWindow
      : traffic === 'normal' ? inWindow.filter(p => !isAnomaly(p))
        : inWindow.filter(isAnomaly)

    // X spans the chosen window even when data doesn't, so switching the
    // dropdown visibly changes scale instead of silently re-fitting.
    return {
      data: shown,
      counts: counted,
      domainX: [start, end] as [number, number],
      scoredCount: rows.length,
      mode: (usingLogs ? 'baseline' : 'detections') as 'baseline' | 'detections',
    }
  }, [logs, alerts, win.ms, traffic, history])

  const chartColumns: Col<ChartPoint>[] = [
    { label: 'Timestamp (UTC)', value: p => new Date(p.time).toISOString() },
    { label: 'Time (MYT)', value: p => formatClockSec(p.time) },
    { label: 'Anomaly score', value: p => p.raw },
    { label: 'Risk %', value: p => Math.round(p.risk) },
    { label: 'Anomalous', value: p => (p.raw < IF_THRESHOLD ? 'Yes' : 'No') },
    { label: 'Source IP', value: p => p.ip },
    { label: 'Event', value: p => p.label },
    { label: 'Severity', value: p => p.severity || '' },
  ]

  const toolbar = (
    <div className="chart-toolbar">
      <Segmented label="Traffic shown"
        options={[
          { key: 'all' as const, label: 'All traffic', count: counts.all },
          { key: 'normal' as const, label: 'Normal', count: counts.normal },
          { key: 'anomaly' as const, label: 'Anomalies', count: counts.anomaly },
        ]}
        value={traffic} onChange={setTraffic} />
      <div className="spacer" />
      <ExportMenu name={`chart-${traffic}`} rows={data} columns={chartColumns} />
      <select aria-label="Chart time range" value={winIdx}
        onChange={e => setWinIdx(Number(e.target.value))}>
        {CHART_WINDOWS.map((w, i) => <option key={w.label} value={i}>{w.label}</option>)}
      </select>
    </div>
  )

  if (data.length === 0) {
    // Four different absences, and conflating them costs debugging time. A
    // filter that excluded everything or a window drawn too tight gets a
    // one-click fix; a feed whose scores won't parse is a pipeline fault and
    // must say so rather than impersonate a quiet portal — that mistake is
    // what "no scored traffic" meant while the log stream was filling up.
    if (counts.all > 0) {
      // The window HAS traffic — the traffic filter excluded all of it. Keep
      // the toolbar on screen so the way back out is the same control that
      // led in, and name the count so the choice is informed.
      const other = traffic === 'normal' ? counts.anomaly : counts.normal
      return (
        <>
          {toolbar}
          <EmptyState
            icon={traffic === 'anomaly' ? <ShieldCheck size={22} /> : <Activity size={22} />}
            title={traffic === 'anomaly'
              ? `No anomalies in the ${win.label.replace(/^Last /, 'last ')}`
              : `No normal traffic in the ${win.label.replace(/^Last /, 'last ')}`}
            body={traffic === 'anomaly'
              ? `All ${counts.all} scored ${plural(counts.all, 'request', 'requests')} in this window stayed under the threshold. That is the state you want.`
              : `Every scored request in this window crossed the threshold (${other} ${plural(other, 'anomaly', 'anomalies')}).`}
            action={<button className="btn" onClick={() => setTraffic('all')}>Show all traffic</button>}
          />
        </>
      )
    }
    if (scoredCount > 0) {
      return (
        <>
          {toolbar}
          <EmptyState
            icon={<Activity size={22} />}
            title={`No traffic in the ${win.label.replace(/^Last /, 'last ')}`}
            body="There is scored traffic outside this window. Widen the range to bring it into view."
            action={winIdx < CHART_WINDOWS.length - 1
              ? <button className="btn" onClick={() => setWinIdx(winIdx + 1)}>Show {CHART_WINDOWS[winIdx + 1].label.toLowerCase()}</button>
              : undefined}
          />
        </>
      )
    }
    if (logs.length > 0 && alerts.length === 0) {
      const d = diagnoseScores(logs)
      return (
        <EmptyState
          icon={<AlertTriangle size={22} />}
          title={d.title}
          body={d.body}
          action={onRunSim && <button className="btn" onClick={onRunSim}>Refresh now</button>}
        />
      )
    }
    return (
      <EmptyState
        icon={<Activity size={22} />}
        title="No scored traffic yet"
        body="Nothing has reached the portal in this window. Run the attack simulator to generate sample traffic, or wait for live requests to arrive."
        action={onRunSim && <button className="btn" onClick={onRunSim}>Refresh now</button>}
      />
    )
  }

  return (
    <>
      {toolbar}
      <div className="chart-wrap">
        {/* Height is stated here rather than inherited: height="100%" against a
            wrapper with no height collapses the plot to nothing. */}
        <ResponsiveContainer width="100%" height={220}>
          <ComposedChart data={data} margin={{ top: 6, right: 12, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--brand)" stopOpacity={0.22} />
                <stop offset="100%" stopColor="var(--brand)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="var(--chart-grid)" vertical={false} />
            <XAxis dataKey="time" type="number" domain={domainX} scale="time"
              tickFormatter={win.days ? formatDay : (win.secTicks ? formatClockSec : formatClock)}
              minTickGap={50} interval="preserveStartEnd"
              axisLine={false} tickLine={false}
              tick={{ fill: 'var(--chart-tick)', fontSize: 12, fontFamily: 'IBM Plex Mono' } as any} />
            <YAxis width={46} axisLine={false} tickLine={false}
              domain={[-RISK_Y_PAD, 100 + RISK_Y_PAD]} ticks={RISK_TICKS} allowDataOverflow
              tickFormatter={(v: number) => `${v}%`}
              tick={{ fill: 'var(--chart-tick)', fontSize: 12, fontFamily: 'IBM Plex Mono' } as any} />
            <Tooltip content={<ChartTooltip />} cursor={{ stroke: 'var(--line-2)', strokeWidth: 1 }} />
            {/* 50% IS the threshold — riskPercentFor anchors it there, same as
                the gauge's centre mark. One scale, three places. */}
            <ReferenceLine y={50} stroke="var(--sev-critical)" strokeDasharray="5 4"
              strokeWidth={1.5} strokeOpacity={0.8} />
            {mode === 'baseline' && traffic !== 'anomaly' ? (
              /* 'linear', not 'monotone': the spline rounded every spike off, and
                 a spike is the entire thing this chart exists to show. */
              <Area type="linear" dataKey="risk" stroke="var(--brand)" strokeWidth={2.2}
                strokeLinejoin="round" strokeLinecap="round" baseValue={-RISK_Y_PAD}
                fill="url(#riskFill)" fillOpacity={1} isAnimationActive={false}
                dot={<BreachDot />} activeDot={{ r: 4 }} />
            ) : (
              /* Anomalies-only view uses dots even when the baseline exists:
                 anomalies are sparse and irregular, and a stroke between two
                 detections would assert risk nobody measured — the same reason
                 detections mode never draws a line. */
              <Scatter dataKey="risk" shape={<SeverityDot />} isAnimationActive={false} />
            )}
          </ComposedChart>
        </ResponsiveContainer>
      </div>
      <div className="legend">
        {mode === 'baseline' && traffic !== 'anomaly' ? (
          <>
            <span><i style={{ background: 'var(--brand)' }} />Risk level{traffic === 'normal' ? ' — normal traffic only' : ''}</span>
            <span><i style={{ background: 'var(--sev-critical)' }} />Alert threshold · 50% (score {num(IF_THRESHOLD, 2)})</span>
            {/* The breach dot only paints below the threshold, which the normal
                filter excludes by definition — so in that tab the swatch would
                point at something the chart can never draw. In All traffic the
                dots are severity-coloured, so the legend names each level. */}
            {traffic === 'all' && SEV_LEVELS.map(k => (
              <span key={k}><i style={{ background: `var(--sev-${k})`, borderRadius: '50%' }} />{titleCase(k)}</span>
            ))}
          </>
        ) : mode === 'baseline' ? (
          <>
            {SEV_LEVELS.map(k => (
              <span key={k}>
                <i style={{ background: `var(--sev-${k})`, borderRadius: '50%' }} />{titleCase(k)}
              </span>
            ))}
            <span><i style={{ background: 'var(--sev-critical)' }} />Alert threshold · 50% (score {num(IF_THRESHOLD, 2)})</span>
          </>
        ) : (
          <>
            <span><i style={{ background: 'var(--sev-critical)', borderRadius: '50%' }} />Detection, by severity</span>
            <span><i style={{ background: 'var(--sev-critical)' }} />Alert threshold · 50% (score {num(IF_THRESHOLD, 2)})</span>
            {/* Naming the limitation beats drawing a line that implies otherwise:
                everything here is already past the threshold, so the empty lower
                half is accurate, not a rendering gap. */}
            <span style={{ color: 'var(--text-3)' }}>
              Detections only — the log stream carries no scores, so there’s no baseline traffic to plot
            </span>
          </>
        )}
      </div>
    </>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Alert list + threat report
   ══════════════════════════════════════════════════════════════════════════ */

function AlertList({ alerts, loading, onSelect, limit = 50 }: {
  alerts: Alert[], loading: boolean, onSelect: (a: Alert) => void, limit?: number
}) {
  const sorted = useMemo(
    () => [...alerts].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')).slice(0, limit),
    [alerts, limit],
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

/* ══════════════════════════════════════════════════════════════════════════
   Alerts page — the full, searchable list (Overview shows only the latest few)
   ══════════════════════════════════════════════════════════════════════════ */

const SEV_RANK: Record<string, number> = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }

function AlertsPanel({ alerts, loading, onSelect, onRefresh }: {
  alerts: Alert[], loading: boolean, onSelect: (a: Alert) => void, onRefresh: () => void
}) {
  const [q, setQ] = useState('')
  // Grouped by default. A sustained attack writes one alert per detection
  // window, so a flat list repeats the same address a dozen times at drifting
  // severities — noise that also made this page look like a second copy of the
  // blocklist. Grouping reframes it as what it actually is: a per-source
  // history. The blocklist answers "who is blocked right now"; this answers
  // "what has this address been doing". Chronological stays one click away for
  // anyone who needs the raw sequence.
  const [grouped, setGrouped] = useState(true)
  const [open, setOpen] = useState<Set<string>>(new Set())
  const toggle = (ip: string) => setOpen(prev => {
    const next = new Set(prev); next.has(ip) ? next.delete(ip) : next.add(ip); return next
  })

  const filtered = useMemo(() => {
    const n = q.toLowerCase().trim()
    return alerts.filter(a => !n || `${a.source_ip} ${a.type} ${a.reason} ${a.severity}`.toLowerCase().includes(n))
  }, [alerts, q])
  const sorted = useMemo(
    () => [...filtered].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')),
    [filtered],
  )

  const groups = useMemo(() => {
    const byIp = new Map<string, Alert[]>()
    for (const a of sorted) {
      const list = byIp.get(a.source_ip)
      if (list) list.push(a); else byIp.set(a.source_ip, [a])
    }
    return [...byIp.entries()].map(([ip, items]) => {
      const worst = items.reduce((w, a) => (SEV_RANK[a.severity] ?? 0) > (SEV_RANK[w] ?? 0) ? a.severity : w, 'LOW')
      const types = [...new Set(items.map(a => a.type).filter(Boolean))]
      return {
        ip, items, worst, types,
        latest: items[0],
        first: items[items.length - 1],
        geo: items[0]?.geo_anomaly,
      }
    }).sort((a, b) => (b.latest.timestamp || '').localeCompare(a.latest.timestamp || ''))
  }, [sorted])

  return (
    <div className="card">
      <div className="toolbar">
        <SearchBox value={q} onChange={setQ} placeholder="Filter by address, type or reason" />
        <span className="count">
          {grouped
            ? `${groups.length} ${plural(groups.length, 'source', 'sources')} · ${filtered.length} ${plural(filtered.length, 'alert', 'alerts')}`
            : `${filtered.length} of ${alerts.length}`}
        </span>
        <div className="seg" role="group" aria-label="Alert grouping">
          <button aria-pressed={grouped} onClick={() => setGrouped(true)}>By source</button>
          <button aria-pressed={!grouped} onClick={() => setGrouped(false)}>Chronological</button>
        </div>
        <ExportMenu name={q ? 'alerts-filtered' : 'alerts'} rows={sorted} columns={ALERT_COLUMNS} />
        <button className="btn sm ghost" onClick={onRefresh} title="Refresh alerts">
          <RefreshCw size={13} />Refresh
        </button>
      </div>

      {!grouped && <AlertList alerts={filtered} loading={loading} onSelect={onSelect} limit={200} />}

      {grouped && (
        loading && alerts.length === 0 ? <Spinner label="Loading alerts…" />
          : groups.length === 0 ? (
            <EmptyState icon={<ShieldCheck size={22} />} title="No alerts"
              body="Nothing has crossed the detection threshold. This is the state you want." />
          ) : (
            <div>
              {groups.map(g => {
                const isOpen = open.has(g.ip)
                return (
                  <div key={g.ip}>
                    <button className={`row r-${sevKey(g.worst)}`} onClick={() => toggle(g.ip)}
                      aria-expanded={isOpen}
                      title={isOpen ? 'Collapse this source' : 'Expand to see each detection'}>
                      <span className="cell-sev"><SeverityPill severity={g.worst} /></span>
                      <span className="cell-ip truncate"><IpCell ip={g.ip} geoAnomaly={g.geo} /></span>
                      <span className="grow">
                        <span className="what">{g.types.slice(0, 2).join(' · ') || 'Detection'}</span>
                        <div className="why truncate">
                          {g.items.length} {plural(g.items.length, 'detection', 'detections')}
                          {g.items.length > 1 && ` · first seen ${formatTime(g.first.timestamp)}`}
                          {` · ${g.latest.reason}`}
                        </div>
                      </span>
                      <span className="when hide-sm">{g.items.length}×</span>
                      <span className="when">{formatTime(g.latest.timestamp)}</span>
                      <ChevronDown size={15} aria-hidden="true"
                        style={{ flexShrink: 0, opacity: 0.55, transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform .15s ease' }} />
                    </button>
                    {isOpen && (
                      <div style={{ paddingLeft: 18 }}>
                        <AlertList alerts={g.items} loading={false} onSelect={onSelect} limit={100} />
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )
      )}
    </div>
  )
}

function ThreatReport({ alert, block, onClose, onUnblock }: {
  alert: Alert, block: BlockedIP | null, onClose: () => void, onUnblock: (ip: string) => void
}) {
  const closeRef = useRef<HTMLButtonElement>(null)
  const [justUnblocked, setJustUnblocked] = useState(false)
  // Live block state: the parent's block list, minus an unblock we just issued
  // (so the button flips the instant it's clicked, ahead of the next poll).
  const isBlocked = !!block && !justUnblocked
  const nowSec = useNowMs(1000) / 1000
  // Blocks are temporary and lift on their own, so the report states WHEN
  // rather than just THAT — otherwise the only visible way out looks like the
  // unblock button, which invites releasing an attacker that would have
  // expired by itself.
  const ttlLabel = useMemo(() => {
    if (!block?.ttl) return null
    const left = Math.max(0, block.ttl - nowSec)
    if (left <= 0) return 'expiring now'
    const h = Math.floor(left / 3600), m = Math.floor((left % 3600) / 60)
    return h > 0 ? `${h}h ${m}m` : `${m}m`
  }, [block, nowSec])
  const foreign = Number(alert.geo_anomaly) === 1 || (alert.geo_anomaly as any) === true || (alert.geo_anomaly as any) === 'true'
  const isML = (alert.method || '').toUpperCase().includes('ML') || (alert.method || '').toLowerCase().includes('isolation')

  const handleUnblockClick = () => {
    onUnblock(alert.source_ip)
    setJustUnblocked(true)
  }

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
          <div className="fact">
            <dt>Current status</dt>
            <dd>{isBlocked ? 'Blocked in AWS WAF' : 'Not currently blocked'}</dd>
          </div>
          <div className="fact">
            <dt>Block lifts in</dt>
            <dd>{isBlocked ? (ttlLabel ?? 'on expiry') : '—'}</dd>
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
          {isBlocked ? (
            <button className="btn primary" onClick={handleUnblockClick}>
              Unblock this address
            </button>
          ) : (
            <button className="btn" disabled title="This address is not on the block list">
              {justUnblocked ? 'Unblocked ✓' : 'Not currently blocked'}
            </button>
          )}
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

/** How many older records one "Load older" click fetches. */
const HISTORY_PAGE = 300
/** Server-side history search stops after this many matches — enough to read,
 *  and a natural point to ask the user to narrow the term instead. */
const SEARCH_MATCH_CAP = 1000

function LogFeed({ logs, loading, error, onRefresh }: {
  logs: LogEntry[], loading: boolean, error: boolean, onRefresh: () => void
}) {
  const [q, setQ] = useState('')

  /* The 4-second poll keeps only the newest slice; everything older lives in
     DynamoDB and is pulled on demand. `older` accumulates those pages;
     `cursor` is where the next page starts (undefined = never fetched,
     null = the database is exhausted). Search runs server-side through the
     WHOLE table so a record from weeks ago is still findable. */
  const [older, setOlder] = useState<LogEntry[]>([])
  const [cursor, setCursor] = useState<string | null | undefined>(undefined)
  const [loadingMore, setLoadingMore] = useState(false)
  const [searchState, setSearchState] = useState<{ running: boolean, scanned: number, done: boolean }>({ running: false, scanned: 0, done: false })
  const searchAbort = useRef(false)

  // A new search term invalidates a finished history search for the old term.
  useEffect(() => {
    searchAbort.current = true
    setSearchState(s => ({ ...s, running: false, done: false }))
  }, [q])
  useEffect(() => () => { searchAbort.current = true }, [])

  const merged = useMemo(() => {
    const byId = new Map<string, LogEntry>()
    for (const l of [...older, ...logs]) byId.set(l.log_id || `${l.timestamp}-${l.message}`, l)
    return [...byId.values()].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
  }, [logs, older])

  const filtered = useMemo(() => {
    const needle = q.toLowerCase().trim()
    return merged.filter(l => !needle || `${l.timestamp} ${l.level} ${l.source_ip} ${l.message} ${l.source || ''}`.toLowerCase().includes(needle))
  }, [merged, q])

  const loadOlder = async () => {
    setLoadingMore(true)
    try {
      const page = await fetchLogPage({ cursor: cursor ?? undefined, limit: HISTORY_PAGE })
      setOlder(prev => [...prev, ...page.items])
      setCursor(page.cursor)
    } catch (e) {
      console.error('Could not load older records:', e)
    } finally {
      setLoadingMore(false)
    }
  }

  /** Walks the whole table server-side, page by page, keeping only matches.
   *  Progress is reported as it goes — a long-running button that says
   *  nothing is indistinguishable from a broken one. */
  const searchHistory = async () => {
    const term = q.trim()
    if (!term) return
    searchAbort.current = false
    setSearchState({ running: true, scanned: 0, done: false })
    let c: string | null | undefined = undefined
    let matches = 0
    try {
      do {
        const page: Awaited<ReturnType<typeof fetchLogPage>> = await fetchLogPage({ q: term, cursor: c ?? undefined })
        if (searchAbort.current) return
        matches += page.items.length
        if (page.items.length) setOlder(prev => [...prev, ...page.items])
        setSearchState(s => ({ ...s, scanned: s.scanned + (page.scanned || 0) }))
        c = page.cursor
      } while (c && matches < SEARCH_MATCH_CAP && !searchAbort.current)
      setSearchState(s => ({ ...s, running: false, done: true }))
    } catch (e) {
      console.error('History search failed:', e)
      setSearchState(s => ({ ...s, running: false }))
    }
  }

  const logColumns: Col<LogEntry>[] = [
    { label: 'Timestamp (UTC)', value: l => l.timestamp },
    { label: 'Time (MYT)', value: l => formatTime(l.timestamp) },
    { label: 'Level', value: l => l.level },
    { label: 'Source IP', value: l => l.source_ip },
    { label: 'Origin', value: l => (Number(l.geo_anomaly) === 1 ? 'Foreign' : 'Malaysia') },
    { label: 'Message', value: l => l.message },
    { label: 'Source', value: l => l.source || '' },
    { label: 'Anomaly score', value: l => (typeof pickScore(l) === 'number' ? pickScore(l)! : '') },
  ]

  if (loading && logs.length === 0) return <Spinner label="Loading log stream…" />

  const dbExhausted = cursor === null
  const countLabel = q
    ? `${filtered.length} of ${merged.length} loaded`
    : `${merged.length} loaded${dbExhausted ? ' · entire history' : ''}`

  return (
    <div className="card">
      <div className="toolbar">
        <SearchBox value={q} onChange={setQ} placeholder={'Filter by address, level or message'} />
        <span className="count">{countLabel}</span>
        <ExportMenu name={q ? 'logs-filtered' : 'logs'} rows={filtered} columns={logColumns} />
        <button className="btn sm ghost" onClick={onRefresh} title="Reconnect to the log stream">
          <RefreshCw size={13} />Reconnect
        </button>
      </div>

      {q && !dbExhausted && (
        <div className="history-bar">
          {searchState.running ? (
            <span className="count"><RefreshCw size={12} className="spin" style={{ verticalAlign: '-2px' }} /> Searching the full history… {searchState.scanned.toLocaleString()} records checked</span>
          ) : searchState.done ? (
            <span className="count">Searched the entire database for “{q}” — every match is shown below</span>
          ) : (
            <>
              <span className="count">Only the {merged.length.toLocaleString()} loaded records are filtered so far</span>
              <button className="btn sm" onClick={searchHistory}>
                <Search size={12} />Search entire history
              </button>
            </>
          )}
        </div>
      )}

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
            title={`No records match “${q}” in the ${merged.length} loaded`}
            body={dbExhausted
              ? 'The entire database has been loaded — nothing matches. Try a partial address like 175.136 or a level like CRITICAL.'
              : 'Older records in the database haven’t been checked yet — search the full history, or clear the filter.'}
            action={
              <div style={{ display: 'flex', gap: 8, justifyContent: 'center' }}>
                {!dbExhausted && (
                  <button className="btn primary" onClick={searchHistory} disabled={searchState.running}>
                    {searchState.running ? <><RefreshCw size={13} className="spin" />Searching…</> : 'Search entire history'}
                  </button>
                )}
                <button className="btn" onClick={() => setQ('')}>Clear filter</button>
              </div>
            }
          />
        ) : (
          <EmptyState
            icon={<Inbox size={22} />}
            title="No log records yet"
            body="Requests to the portal will appear here within a few seconds of arriving. Run the attack simulator to generate sample traffic."
          />
        )
      ) : (
        <>
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
          <div className="loadmore">
            {dbExhausted ? (
              <span className="count">End of history — every record in the database is loaded</span>
            ) : (
              <button className="btn" onClick={loadOlder} disabled={loadingMore}>
                {loadingMore
                  ? <><RefreshCw size={13} className="spin" />Loading older records…</>
                  : <>Load {HISTORY_PAGE} older records</>}
              </button>
            )}
          </div>
        </>
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

  // Remediation history must be DURABLE, not a slice of the live window. The
  // 4-second poll only holds the newest ~300 rows, so a fresh unblock's AUDIT
  // line drops off the view as soon as 300 newer log rows arrive — which read
  // as "remediation never updates". So we ALSO pull unblock audit rows
  // server-side (they persist across polls) and merge them with any live AUDIT
  // rows for immediate feedback. Re-runs whenever the block list changes.
  const [remediation, setRemediation] = useState<LogEntry[]>([])
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const page = await fetchLogPage({ q: 'UNBLOCKED', limit: 100 })
        if (!cancelled) setRemediation(page.items)
      } catch { /* keep whatever we already have */ }
    })()
    return () => { cancelled = true }
  }, [ips])

  const auditLogs = useMemo(() => {
    const byId = new Map<string, LogEntry>()
    for (const l of [...remediation, ...logs.filter(l => l.level === 'AUDIT')]) {
      byId.set(l.log_id || `${l.timestamp}-${l.message}`, l)
    }
    return [...byId.values()]
      .sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
      .slice(0, 50)
  }, [logs, remediation])

  const expiringSoon = sortedIPs.filter(i => i.ttl && i.ttl - now > 0 && i.ttl - now < 600).length

  const handleUnblock = async (ip: string) => {
    setPending(ip)
    try { await onUnblock(ip) } finally { setPending(null) }
  }

  const blockColumns: Col<BlockedIP>[] = [
    { label: 'IP address', value: b => b.ip },
    { label: 'Severity', value: b => b.severity },
    { label: 'Origin', value: b => (Number(b.geo_anomaly) === 1 ? 'Foreign' : 'Malaysia') },
    { label: 'Blocked at (UTC)', value: b => b.blocked_at },
    { label: 'Blocked at (MYT)', value: b => formatTime(b.blocked_at) },
    { label: 'Expires (UTC)', value: b => (b.ttl ? new Date(b.ttl * 1000).toISOString() : '') },
    { label: 'Anomaly score', value: b => b.score },
    { label: 'Reason', value: b => b.reason },
  ]

  if (loading && ips.length === 0) return <Spinner label="Loading blocked addresses…" />

  return (
    <div className="stack">
      <div className="card">
        <div className="toolbar">
          <SearchBox value={q} onChange={setQ} placeholder="Filter blocked addresses by IP, reason or severity" />
          <span className="count">
            {sortedIPs.length} blocked{expiringSoon > 0 ? ` · ${expiringSoon} expiring soon` : ''}
          </span>
          <ExportMenu name={q ? 'blocked-ips-filtered' : 'blocked-ips'} rows={sortedIPs} columns={blockColumns} />
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
              // Fraction of THIS block's own sentence, not of the 4h maximum.
              // Dividing by 4h meant a fresh 1h MEDIUM block rendered a quarter-
              // full grey bar that never visibly moved — which is why it read as
              // a broken decoration instead of a countdown. Full at block time,
              // draining to empty at expiry, one width tick per second.
              const startSec = item.blocked_at ? parseTS(item.blocked_at).getTime() / 1000 : NaN
              const total = item.ttl && Number.isFinite(startSec) ? Math.max(1, item.ttl - startSec) : 0
              const pct = total > 0 ? clamp((timeLeft / total) * 100, 0, 100) : 0

              return (
                <div key={`${item.ip}-${i}`} className={`block-row r-${sevKey(item.severity)}`}>
                  <span className="cell-sev"><SeverityPill severity={item.severity} /></span>
                  <span className="cell-ip"><IpCell ip={item.ip} geoAnomaly={item.geo_anomaly} /></span>
                  <span className="grow truncate block-reason">{item.reason}</span>
                  <span className="ttl">
                    <span className={`t ${timeLeft <= 0 ? 'expired' : ''}`}>
                      {timeLeft > 0 ? label : 'Expired — clearing'}
                    </span>
                    <span className="track" role="progressbar"
                      aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(pct)}
                      aria-label={`Block time remaining for ${item.ip}`}>
                      <span className="fill" style={{
                        width: `${pct}%`,
                        background: `var(--sev-${sevKey(item.severity)})`,
                      }} />
                    </span>
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

function CriticalToast({ alert, total, index, remaining, onView, onDismiss, onDismissAll }: {
  alert: Alert, total: number, index: number, remaining: number,
  onView: () => void, onDismiss: () => void, onDismissAll: () => void
}) {
  return (
    <div className="toast" role="status" aria-live="polite">
      <div className="toast-head">
        <ShieldCheck size={16} strokeWidth={2.2} aria-hidden="true" />
        Threat blocked automatically
        {total > 1 && <span className="count" style={{ color: 'inherit' }}>{index} of {total}</span>}
        <div className="spacer" />
        <button className="btn ghost sm" onClick={onDismiss}
          aria-label={remaining > 1 ? 'Dismiss this notification and show the next' : 'Dismiss notification'}
          title={remaining > 1 ? 'Dismiss this one' : 'Dismiss'}
          style={{ color: 'inherit', margin: '-3px -5px' }}>
          <X size={14} />
        </button>
      </div>
      <div className="toast-body">
        <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 3 }}>{alert.type}</div>
        <IpCell ip={alert.source_ip} geoAnomaly={alert.geo_anomaly} />
        <p style={{ fontSize: 12.5, color: 'var(--text-2)', marginTop: 9 }}>
          Sentinel blocked this at the WAF automatically — nothing to do. Open it only if you think it’s a false positive and want to unblock.
        </p>
        <div className="toast-actions">
          <button className="btn primary" onClick={onView}>Review</button>
          <button className="btn" onClick={onDismiss}>{remaining > 1 ? 'Next' : 'Dismiss'}</button>
          {remaining > 1 && (
            <button className="btn ghost" onClick={onDismissAll}
              title="Dismiss every remaining notification">Dismiss all ({remaining})</button>
          )}
        </div>
      </div>
    </div>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Dashboard
   ══════════════════════════════════════════════════════════════════════════ */

const ALERT_COLUMNS: Col<Alert>[] = [
  { label: 'Timestamp (UTC)', value: a => a.timestamp },
  { label: 'Time (MYT)', value: a => formatTime(a.timestamp) },
  { label: 'Severity', value: a => a.severity },
  { label: 'Threat type', value: a => a.type },
  { label: 'Source IP', value: a => a.source_ip },
  { label: 'Origin', value: a => (Number(a.geo_anomaly) === 1 ? 'Foreign' : 'Malaysia') },
  { label: 'Anomaly score', value: a => a.score },
  { label: 'Detected by', value: a => ((a.method || '').toUpperCase().includes('ML') || (a.method || '').toLowerCase().includes('isolation') ? 'Isolation Forest' : 'Rule engine') },
  { label: 'Reason', value: a => a.reason },
  { label: 'Status', value: a => a.status },
]

function UsersPanel({ myEmail }: { myEmail: string }) {
  const [users, setUsers] = useState<ManagedUser[] | null>(null)
  const [domains, setDomains] = useState<DomainAllow[]>([])
  const [error, setError] = useState('')
  const [msg, setMsg] = useState('')
  const [busy, setBusy] = useState('')                 // email (or '__invite__') mid-action
  const [confirmRemove, setConfirmRemove] = useState('')
  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState<ManagedRole>('operator')

  const load = useCallback(async () => {
    setError('')
    try {
      const r = await listUsers()
      setUsers(r.users)
      setDomains(r.domains)
    } catch (e: any) {
      setError(e?.message || 'Could not load the team list.')
    }
  }, [])

  useEffect(() => { load() }, [load])

  const flash = (m: string) => { setMsg(m); window.setTimeout(() => setMsg(''), 5000) }

  const doInvite = async () => {
    const email = inviteEmail.trim().toLowerCase()
    if (!email) return
    const dup = email.startsWith('@')
      ? domains.some(d => d.domain === email)
      : (users || []).some(u => u.email === email)
    if (dup) { setError(`${email} is already on the team.`); return }
    setBusy('__invite__'); setError('')
    try {
      await inviteUser(email, inviteRole)
      setInviteEmail('')
      flash(`Invited ${email} as ${inviteRole}. They can sign in with Google using this address.`)
      await load()
    } catch (e: any) { setError(e?.message || 'Invite failed.') }
    finally { setBusy('') }
  }

  const doSetRole = async (email: string, role: ManagedRole) => {
    setBusy(email); setError('')
    try {
      const r = await setUserRole(email, role)
      flash(r.note ? `${email}: ${r.note}` : `${email} is now ${role}.`)
      await load()
    } catch (e: any) { setError(e?.message || 'Role change failed.') }
    finally { setBusy('') }
  }

  const doRemove = async (email: string) => {
    setBusy(email); setError(''); setConfirmRemove('')
    try {
      await removeUser(email)
      flash(`Removed ${email}.`)
      await load()
    } catch (e: any) { setError(e?.message || 'Remove failed.') }
    finally { setBusy('') }
  }

  const field: React.CSSProperties = {
    height: 34, padding: '0 12px', borderRadius: 7,
    border: '1px solid var(--line-2)', background: 'var(--panel)', color: 'var(--text)',
    font: "400 13px/1 'IBM Plex Sans', sans-serif",
  }

  if (users === null && !error) return <Spinner label="Loading team…" />
  const list = users || []

  return (
    <div className="stack">
      <div className="card">
        <div className="toolbar">
          <span className="card-title"><Users size={15} color="var(--brand)" aria-hidden="true" /> Team access</span>
          <span className="count">{list.length} {list.length === 1 ? 'person' : 'people'}</span>
          <div className="spacer" />
          <button className="btn sm ghost" onClick={load} title="Refresh"><RefreshCw size={13} />Refresh</button>
        </div>

        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', padding: 16, paddingBottom: 0, alignItems: 'center' }}>
          <input type="email" value={inviteEmail} onChange={e => setInviteEmail(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') doInvite() }}
            placeholder="name@example.com  (or @domain.com for a whole domain)"
            aria-label="Email to invite" style={{ ...field, flex: '1 1 260px' }} />
          <select value={inviteRole} onChange={e => setInviteRole(e.target.value as ManagedRole)}
            aria-label="Role" style={field}>
            <option value="operator">Operator</option>
            <option value="admin">Admin</option>
          </select>
          <button className="btn primary" onClick={doInvite} disabled={busy === '__invite__' || !inviteEmail.trim()}>
            <UserPlus size={14} />{busy === '__invite__' ? 'Inviting…' : 'Invite'}
          </button>
        </div>
        <p className="modal-note" style={{ padding: '10px 16px 0' }}>
          Invited people sign in with Google — no password needed. Role changes apply after the person signs out and back in.
        </p>

        {msg && (
          <div className="form-error" style={{ margin: 16, marginBottom: 0, color: 'var(--ok)' }} role="status">
            <CheckCircle2 size={15} aria-hidden="true" /><span>{msg}</span>
          </div>
        )}
        {error && (
          <div className="form-error" style={{ margin: 16, marginBottom: 0 }} role="alert">
            <AlertTriangle size={15} aria-hidden="true" /><span>{error}</span>
          </div>
        )}

        {list.length === 0 ? (
          <EmptyState icon={<Users size={22} />} title="No one on the team yet"
            body="Invite a teammate by email above. They’ll sign in with Google — no password to share." />
        ) : (
          <div style={{ padding: 16 }}>
            {list.map(u => {
              const isSelf = u.email === myEmail
              const isAdminRow = u.role === 'admin'
              const acting = busy === u.email
              return (
                <div key={u.email} style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap', padding: '10px 0', borderBottom: '1px solid var(--line)' }}>
                  <div style={{ flex: '1 1 220px', minWidth: 0 }}>
                    <div style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {u.email}{isSelf && <span className="chip" style={{ marginLeft: 8 }}>You</span>}
                    </div>
                    <div className="mono" style={{ fontSize: 12, opacity: 0.7 }}>
                      {u.joined ? 'Active' : 'Invited — not signed in yet'}{u.accounts.some(a => a.federated) ? ' · Google' : ''}
                    </div>
                  </div>

                  <span className="chip" style={isAdminRow ? { color: 'var(--brand)', borderColor: 'var(--brand)' } : (!u.joined ? { opacity: 0.6 } : undefined)}>
                    {isAdminRow ? <ShieldCheck size={13} /> : <Shield size={13} />}
                    {u.role === '—' ? 'Pending' : u.role.charAt(0).toUpperCase() + u.role.slice(1)}
                  </span>

                  {u.joined && (isAdminRow ? (
                    <button className="btn sm" disabled={acting || isSelf}
                      title={isSelf ? 'You cannot remove your own admin access' : 'Demote to operator'}
                      onClick={() => doSetRole(u.email, 'operator')}>
                      {acting ? '…' : 'Make operator'}
                    </button>
                  ) : (
                    <button className="btn sm" disabled={acting}
                      title="Promote to admin" onClick={() => doSetRole(u.email, 'admin')}>
                      {acting ? '…' : 'Make admin'}
                    </button>
                  ))}

                  {confirmRemove === u.email ? (
                    <span style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                      <span style={{ fontSize: 12 }}>Remove?</span>
                      <button className="btn sm" disabled={acting} style={{ color: 'var(--sev-critical-fg)', borderColor: 'var(--sev-critical-fg)' }}
                        onClick={() => doRemove(u.email)}>
                        {acting ? 'Removing…' : 'Yes, remove'}
                      </button>
                      <button className="btn sm ghost" onClick={() => setConfirmRemove('')}>Cancel</button>
                    </span>
                  ) : (
                    <button className="btn sm ghost" disabled={acting || isSelf}
                      title={isSelf ? 'You cannot remove your own account' : 'Revoke access and delete account'}
                      onClick={() => setConfirmRemove(u.email)} aria-label={`Remove ${u.email}`}>
                      <Trash2 size={13} />
                    </button>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

function DashboardView({ onLogout, theme, toggleTheme, role }: { onLogout: () => void, theme: Theme, toggleTheme: () => void, role: Role }) {
  const isAdmin = role === 'admin'
  const { data: alerts, status: alertsStatus, reset: resetAlerts } = usePolling<Alert[]>(fetchAlerts, [], { intervalMs: 4000 })
  const { data: blockedIPs, status: blockedStatus, reset: resetBlocked } = usePolling<BlockedIP[]>(fetchBlockedIPs, [], { intervalMs: 4000 })
  const { data: logs, status: logsStatus, reset: resetLogs } = usePolling<LogEntry[]>(fetchLogs, [], { intervalMs: 4000 })

  const connected = alertsStatus === 'open' && logsStatus === 'open' && blockedStatus === 'open'
  const anyError = alertsStatus === 'error' || logsStatus === 'error' || blockedStatus === 'error'
  const ipsError = blockedStatus === 'error'
  const logsError = logsStatus === 'error'

  const [tab, setTab] = useState<'overview' | 'alerts' | 'logs' | 'blocklist' | 'users'>('overview')
  const protectedAppUrl = import.meta.env.VITE_PROTECTED_APP_URL as string | undefined
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null)
  // The signed-in admin's own email — used to stop them removing or demoting
  // their own account and locking themselves out.
  const [myEmail, setMyEmail] = useState('')
  useEffect(() => { let c = false; getEmail().then(e => { if (!c) setMyEmail(e) }); return () => { c = true } }, [])

  const handleUnblock = async (ip: string) => { await unblockIP(ip); resetBlocked(); resetLogs() }
  const criticalAlerts = (alerts as Alert[]).filter(a => a.severity === 'CRITICAL')
  // "Active" = the source IP is still on the block list. A critical whose IP has
  // been unblocked (manually or by TTL) is handled, so it drops out of the
  // attention signals — the bell, the toast and the sidebar badge — while
  // staying in the Alerts list as a historical record.
  const blockedSet = useMemo(() => new Set((blockedIPs as BlockedIP[]).map(b => b.ip)), [blockedIPs])
  // The interrupting toast and bell stay CRITICAL-only: an interruption should
  // be reserved for the severity that warrants one. Lower severities are still
  // threats, but they are visible in the Alerts list rather than shoved forward.
  // One notification per ADDRESS, not per alert. A source that is blocked,
  // expires and is caught again — or that escalates in severity — writes a
  // second alert row, and stepping through "1 of 2" showing the same IP twice
  // asks the operator to decide the same thing twice. The action they can take
  // (unblock) is per-address, so the notification is too; the newest alert wins
  // and the full history stays on the Alerts page.
  const activeCriticals = useMemo(() => {
    const byIp = new Map<string, Alert>()
    for (const a of criticalAlerts) {
      if (!blockedSet.has(a.source_ip)) continue
      const prev = byIp.get(a.source_ip)
      if (!prev || (a.timestamp || '') > (prev.timestamp || '')) byIp.set(a.source_ip, a)
    }
    return [...byIp.values()].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''))
  }, [criticalAlerts, blockedSet])
  const sortedAlerts = useMemo(
    () => [...(alerts as Alert[])].sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || '')),
    [alerts],
  )

  // Dismissal hides the NOTIFICATION only — never the alert itself. The alert
  // stays in the log and the IP stays blocked. Tracked per alert_id so a NEW
  // critical still surfaces, and held in component state (not persisted) so a
  // reload re-surfaces anything still outstanding. Silencing a critical
  // security alert permanently with one click would be an anti-pattern.
  const [dismissedIds, setDismissedIds] = useState<Set<string>>(new Set())
  const pendingCriticals = activeCriticals.filter(a => !dismissedIds.has(a.alert_id))
  const activeCritical = pendingCriticals[0]
  // "1 of 3" must advance as you step through, so the position is the alert's
  // index in the WHOLE batch, not in what's left — otherwise dismissing one
  // just re-renders "1 of 3" with a different alert behind it.
  const criticalIndex = activeCritical
    ? activeCriticals.findIndex(a => a.alert_id === activeCritical.alert_id) + 1
    : 0
  const dismissCritical = useCallback((...ids: string[]) => {
    setDismissedIds(prev => { const next = new Set(prev); ids.forEach(id => next.add(id)); return next })
  }, [])

  const [navCollapsed, setNavCollapsed] = useState(false)

  // Grouped sidebar nav. Monitor = the two watch surfaces, Respond = the
  // remediation surface, Admin = user management (admins only). Same four tab
  // ids as before — only the presentation moved from a horizontal strip to a
  // grouped rail.
  const NAV_GROUPS = [
    { label: 'Monitor', items: [
      { id: 'overview' as const, label: 'Overview', icon: Activity },
      { id: 'alerts' as const, label: 'Alerts', icon: Bell },
      { id: 'logs' as const, label: 'Log stream', icon: Terminal },
    ] },
    { label: 'Respond', items: [
      { id: 'blocklist' as const, label: 'Blocked IPs', icon: Ban, badge: (blockedIPs as BlockedIP[]).length },
    ] },
    ...(isAdmin ? [{ label: 'Admin', items: [
      { id: 'users' as const, label: 'Users', icon: Users },
    ] }] : []),
  ]

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <div className="mark"><Shield size={15} strokeWidth={2.2} aria-hidden="true" /></div>
          <div className="wordmark">ACS Sentinel</div>
          <div className="spacer" />

          {activeCriticals.length > 0 && dismissedIds.size > 0 && (
            <button className="btn sm ghost" onClick={() => setDismissedIds(new Set())}
              title={`Show ${activeCriticals.length} active critical ${plural(activeCriticals.length, 'alert', 'alerts')}`}
              style={{ color: 'var(--sev-critical-fg)' }}>
              <Bell size={14} />{activeCriticals.length}
            </button>
          )}

          <div className={`chip hide-sm ${connected ? 'is-live' : anyError ? 'is-error' : 'is-wait'}`}>
            <span className="dot" />
            {connected ? <><Wifi size={13} aria-hidden="true" />Live</>
              : anyError ? <><WifiOff size={13} aria-hidden="true" />Reconnecting</>
                : <><RefreshCw size={13} className="spin" aria-hidden="true" />Connecting</>}
          </div>

          <ThemeButton theme={theme} toggleTheme={toggleTheme} />

        </div>
      </header>

      <div className="shell">
        <nav className="sidebar" data-collapsed={navCollapsed} aria-label="Dashboard sections">
          <button className="nav-collapse" onClick={() => setNavCollapsed(v => !v)}
            aria-label={navCollapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-expanded={!navCollapsed}
            title={navCollapsed ? 'Expand' : 'Collapse'}>
            <ChevronsLeft size={16} aria-hidden="true" />
          </button>
          {NAV_GROUPS.map(g => (
            <div className="nav-group" key={g.label}>
              <div className="nav-label">{g.label}</div>
              {g.items.map(it => (
                <button key={it.id} className="nav-item" aria-current={tab === it.id ? 'page' : undefined}
                  onClick={() => setTab(it.id)} title={('hint' in it && it.hint) ? it.hint : it.label}>
                  <it.icon size={16} aria-hidden="true" />
                  <span className="nav-text">{it.label}</span>
                  {'badge' in it && !!it.badge && it.badge > 0 && <span className="nav-badge">{it.badge}</span>}
                </button>
              ))}
            </div>
          ))}

          <div className="nav-foot">
            {protectedAppUrl && (
              <a className="nav-item" href={protectedAppUrl} target="_blank" rel="noreferrer"
                title="Open the protected application">
                <ExternalLink size={16} aria-hidden="true" />
                <span className="nav-text">Protected app</span>
              </a>
            )}
            <div className="nav-acct" title={isAdmin ? 'Administrator — full access' : 'Operator — monitoring and remediation'}>
              {isAdmin ? <ShieldCheck size={16} aria-hidden="true" /> : <Shield size={16} aria-hidden="true" />}
              <span className="nav-text">{isAdmin ? 'Admin' : 'Operator'}</span>
              <button className="nav-signout" onClick={onLogout} title="Sign out" aria-label="Sign out">
                <LogOut size={16} aria-hidden="true" />
              </button>
            </div>
          </div>
        </nav>

        <main className="main">
        {tab === 'overview' && (
          <div className="stack">
            <StatusBand alerts={alerts as Alert[]} blockedIPs={blockedIPs as BlockedIP[]}
              logs={logs as LogEntry[]} anyError={anyError} connected={connected} />
            <SeverityLedger alerts={alerts as Alert[]} />
            <div className="card">
              <div className="card-head">
                <span className="card-title">Anomaly score timeline</span>
                <span className="card-hint hide-sm">Malaysia time</span>
                <div className="spacer" />
                <button className="btn sm ghost" onClick={resetLogs} title="Refresh now">
                  <RefreshCw size={13} />Refresh
                </button>
              </div>
              <AnomalyChart logs={logs as LogEntry[]} alerts={alerts as Alert[]} onRunSim={resetLogs} />
            </div>

            <div className="card">
              <div className="card-head">
                <span className="card-title">Recent alerts</span>
                <span className="card-hint hide-sm">Latest 5 — select a row for the full report</span>
                <div className="spacer" />
                <button className="btn sm ghost" onClick={() => setTab('alerts')} title="See every alert">
                  View all →
                </button>
              </div>
              <AlertList alerts={sortedAlerts} loading={alertsStatus === 'connecting'} onSelect={setSelectedAlert} limit={5} />
            </div>
          </div>
        )}

        {tab === 'alerts' && (
          <AlertsPanel alerts={alerts as Alert[]} loading={alertsStatus === 'connecting'}
            onSelect={setSelectedAlert} onRefresh={resetAlerts} />
        )}

        {tab === 'logs' && (
          <LogFeed logs={logs as LogEntry[]} loading={logsStatus === 'connecting'} error={logsError} onRefresh={resetLogs} />
        )}

        {tab === 'blocklist' && (
          <BlocklistPanel ips={blockedIPs as BlockedIP[]} logs={logs as LogEntry[]}
            loading={blockedStatus === 'connecting'} error={ipsError}
            onUnblock={handleUnblock} onRefresh={resetBlocked} />
        )}

        {tab === 'users' && isAdmin && (
          <UsersPanel myEmail={myEmail} />
        )}

        <footer className="foot">
          <ShieldCheck size={13} color="var(--ok)" aria-hidden="true" />
          Automatic blocking is on
          <div className="spacer" />
          <span className="mono">MYT (UTC+8)</span>
        </footer>
        </main>
      </div>

      {activeCritical && (
        <CriticalToast alert={activeCritical} total={activeCriticals.length}
          index={criticalIndex} remaining={pendingCriticals.length}
          onView={() => { setSelectedAlert(activeCritical); dismissCritical(activeCritical.alert_id) }}
          onDismiss={() => dismissCritical(activeCritical.alert_id)}
          onDismissAll={() => dismissCritical(...pendingCriticals.map(a => a.alert_id))} />
      )}

      {selectedAlert && (
        <ThreatReport alert={selectedAlert}
          block={(blockedIPs as BlockedIP[]).find(b => b.ip === selectedAlert.source_ip) ?? null}
          onClose={() => setSelectedAlert(null)} onUnblock={handleUnblock} />
      )}
    </>
  )
}

/* ══════════════════════════════════════════════════════════════════════════
   Root
   ══════════════════════════════════════════════════════════════════════════ */

/* ══════════════════════════════════════════════════════════════════════════
   Returning from the identity provider
   ══════════════════════════════════════════════════════════════════════════ */

/* The token exchange takes a beat, and a blank screen during it reads as a
   failed sign-in — the operator has just handed over their identity and gets
   nothing back. Name the step instead, so the wait is accounted for. */
function VerifyingScreen({ theme, toggleTheme }: { theme: Theme, toggleTheme: () => void }) {
  return (
    <div className="login-wrap">
      <div style={{ position: 'fixed', top: 16, right: 16 }}>
        <ThemeButton theme={theme} toggleTheme={toggleTheme} />
      </div>
      <div className="login" style={{ textAlign: 'center' }} role="status" aria-live="polite">
        <div className="login-mark" style={{ margin: '0 auto' }}><Shield size={22} strokeWidth={2.2} /></div>
        <h1 style={{ textAlign: 'center' }}>Sign in to ACS Sentinel</h1>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, marginTop: 18, color: 'var(--text-muted)', fontSize: 14 }}>
          <RefreshCw size={15} className="spin" aria-hidden="true" />
          <span>Verifying your Google account…</span>
        </div>
        <p style={{ fontSize: 12, color: 'var(--text-dim)', marginTop: 10 }}>
          Checking that this account is authorised for this console.
        </p>
      </div>
    </div>
  )
}

export default function App() {
  const [authenticated, setAuthenticated] = useState(false)
  const [booting, setBooting] = useState(true)
  const [oauthError, setOauthError] = useState('')
  // Captured at first render, before completeOAuthRedirect() strips the query
  // string — otherwise there is no way to tell a returning operator apart from
  // an ordinary page load.
  const [returningFromIdP] = useState(() => {
    try { return new URLSearchParams(window.location.search).has('code') } catch { return false }
  })
  const [theme, setTheme] = useState<Theme>(() => {
    try { return (localStorage.getItem('acs-theme') as Theme) || 'dark' } catch { return 'dark' }
  })
  useEffect(() => { applyTheme(theme); try { localStorage.setItem('acs-theme', theme) } catch { } }, [theme])
  const toggleTheme = useCallback(() => setTheme(t => (t === 'dark' ? 'light' : 'dark')), [])

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        // Returning from Google: consume ?code= before anything renders, or the
        // login screen flashes over what is already a valid session.
        if (await completeOAuthRedirect()) {
          if (!cancelled) { setAuthenticated(true); setBooting(false) }
          return
        }
      } catch (e: any) {
        // Includes the PreSignUp allowlist denial, which Cognito returns as
        // error_description on the redirect.
        if (!cancelled) setOauthError(e?.message || 'Google sign-in failed.')
      }
      // Restore an existing session. Required rather than cosmetic: the Google
      // redirect is a full page load, and a refresh should not sign an operator
      // out while their JWT is still valid.
      const ok = await isAuthenticated()
      if (!cancelled) { setAuthenticated(ok); setBooting(false) }
    })()
    return () => { cancelled = true }
  }, [])

  if (booting) {
    // Blank on a cold load — it resolves in milliseconds and a flashed spinner
    // reads as jank. But a returning operator has waited on Google and needs to
    // see that something is happening.
    return returningFromIdP
      ? <VerifyingScreen theme={theme} toggleTheme={toggleTheme} />
      : <div className="login-wrap" />
  }

  if (!authenticated) return <LoginScreen onLogin={() => setAuthenticated(true)} theme={theme} toggleTheme={toggleTheme} initialError={oauthError} />
  return <Dashboard onLogout={() => { signOut(); setAuthenticated(false) }} theme={theme} toggleTheme={toggleTheme} />
}

function Dashboard(props: { onLogout: () => void, theme: Theme, toggleTheme: () => void }) {
  // Resolve the caller's role once the session exists. Defaults to the least
  // privilege (operator) until the token is read, so the unblock controls never
  // flash as enabled for a non-admin during the first paint.
  const [role, setRole] = useState<Role>('operator')
  useEffect(() => {
    let cancelled = false
    getRole().then(r => { if (!cancelled) setRole(r) })
    return () => { cancelled = true }
  }, [])
  return <DashboardView {...props} role={role} />
}
