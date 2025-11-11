import { useEffect, useMemo, useState } from 'react'
import { useAuth } from '@/lib/auth-context'
import { useServices } from '@/services/hooks'
import { ShieldAlert } from 'lucide-react'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Area, AreaChart, Legend } from 'recharts'

function useJson<T>(url: string | null, intervalMs = 15000) {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let cancel = false
    let timer: ReturnType<typeof setInterval> | undefined
    async function load() {
      if (!url) return
      setLoading(true); setError(null)
      try {
        const r = await fetch(url, { credentials: 'include' })
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        const d = await r.json()
        if (!cancel) setData(d)
      } catch (e: unknown) {
        if (!cancel) setError(String((e as Error)?.message || String(e)))
      } finally {
        if (!cancel) setLoading(false)
      }
    }
    load()
    if (intervalMs > 0) timer = setInterval(load, intervalMs)
    return () => { cancel = true; if (timer) clearInterval(timer) }
  }, [url, intervalMs])
  return { data, loading, error }
}

export default function ServerInfoCharts() {
  const { user } = useAuth()
  const services = useServices()

  // hooks must run unconditionally at the top of the component
  const [refreshMs, setRefreshMs] = useState<number>(15000)
  useEffect(() => {
    let cancel = false
    ;(async () => {
      try {
        const s = await services.admin.settings.loadSettings('monitoring')
        const val = Number(s?.monitoring?.chartsRefreshSec ?? 15)
        if (!cancel && Number.isFinite(val) && val > 0) setRefreshMs(val * 1000)
      } catch (err) {
        void err
      }
    })()
    return () => { cancel = true }
  }, [services])

  type Metrics = { requests?: { count?: number; errors?: number; p99?: number } }
  type SeriesPoint = { createdAt: string; value: number }
  type Series = { points?: SeriesPoint[] }

  const { data: metrics, loading: loadingSnap } = useJson<Metrics>('/admin/monitoring/metrics', refreshMs)
  const { data: p99Series } = useJson<Series>('/admin/monitoring/series?metric=http.p99&minutes=120', refreshMs)
  const { data: errSeries } = useJson<Series>('/admin/monitoring/series?metric=http.error_rate&minutes=120', refreshMs)
  const { data: lagSeries } = useJson<Series>('/admin/monitoring/series?metric=eventloop.lag.mean&minutes=120', refreshMs)

  const p99 = useMemo(() => (p99Series?.points || []).map((p: SeriesPoint) => ({ t: new Date(p.createdAt).toLocaleTimeString(), v: p.value })), [p99Series])
  const err = useMemo(() => (errSeries?.points || []).map((p: SeriesPoint) => ({ t: new Date(p.createdAt).toLocaleTimeString(), v: p.value })), [errSeries])
  const lag = useMemo(() => (lagSeries?.points || []).map((p: SeriesPoint) => ({ t: new Date(p.createdAt).toLocaleTimeString(), v: p.value })), [lagSeries])

  const isSystemAdmin = !!user?.roles?.includes('system_admin')
  if (!isSystemAdmin) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 text-red-600 dark:text-red-400"><ShieldAlert className="h-5 w-5" /> Access denied</div>
        <p className="text-sm text-muted-foreground mt-2">This page is restricted to system administrators.</p>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-8">
      <div>
        <h1 className="text-2xl font-semibold">Server Info</h1>
  <p className="text-muted-foreground">Live metrics and recent history. Sampling every ~30s, refresh every {Math.round(refreshMs/1000)}s.</p>
      </div>
      {(loadingSnap && !metrics) && <div className="rounded border p-4 text-sm">Loading metrics…</div>}
      {(!loadingSnap && !metrics) && <div className="rounded border p-4 text-sm">No metrics yet. Keep the server running and make a few requests; data is persisted every ~30 seconds.</div>}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded border p-4">
          <div className="text-sm text-muted-foreground">Requests</div>
          <div className="text-2xl font-semibold">{metrics?.requests?.count ?? '—'}</div>
        </div>
        <div className="rounded border p-4">
          <div className="text-sm text-muted-foreground">Errors</div>
          <div className="text-2xl font-semibold">{metrics?.requests?.errors ?? '—'}</div>
        </div>
        <div className="rounded border p-4">
          <div className="text-sm text-muted-foreground">P99 (ms)</div>
          <div className="text-2xl font-semibold">{metrics?.requests?.p99 ? metrics.requests.p99.toFixed(0) : '—'}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="rounded border p-4">
          <h2 className="font-medium mb-2">HTTP P99 latency (ms)</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={p99} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="p99" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#4F46E5" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#4F46E5" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="t" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Area type="monotone" dataKey="v" stroke="#4F46E5" fillOpacity={1} fill="url(#p99)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="rounded border p-4">
          <h2 className="font-medium mb-2">Error rate</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={err} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="t" tick={{ fontSize: 12 }} />
                <YAxis domain={[0, 'auto']} tick={{ fontSize: 12 }} />
                <Tooltip />
                <Line type="monotone" dataKey="v" stroke="#EF4444" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        <div className="rounded border p-4 md:col-span-2">
          <h2 className="font-medium mb-2">Event loop lag (ms avg)</h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={lag} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="t" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Legend />
                <Line type="monotone" name="lag" dataKey="v" stroke="#10B981" dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  )
}
