import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Calendar, Filter, RefreshCcw, Search, Shield } from 'lucide-react'

type AuditLog = {
  id: string
  createdAt: string
  action: string
  userId?: string | null
  ipAddress?: string | null
  userAgent?: string | null
  metadata?: any
}

type Page<T> = { items: T[]; total: number; page: number; pageSize: number }

export default function AuditLogsPage() {
  const [params, setParams] = useSearchParams()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(() => Number(params.get('page') || 1))
  const [pageSize, setPageSize] = useState(() => Number(params.get('pageSize') || 25))
  const [query, setQuery] = useState(params.get('q') || '')
  const [action, setAction] = useState(params.get('action') || '')
  const [userId, setUserId] = useState(params.get('userId') || '')
  const [from, setFrom] = useState(params.get('from') || '')
  const [to, setTo] = useState(params.get('to') || '')
  const [data, setData] = useState<Page<AuditLog>>({ items: [], total: 0, page: 1, pageSize: 25 })

  // Sync URL
  useEffect(() => {
    const p = new URLSearchParams()
    if (page > 1) p.set('page', String(page))
    if (pageSize !== 25) p.set('pageSize', String(pageSize))
    if (query) p.set('q', query)
    if (action) p.set('action', action)
    if (userId) p.set('userId', userId)
    if (from) p.set('from', from)
    if (to) p.set('to', to)
    setParams(p, { replace: true })
  }, [page, pageSize, query, action, userId, from, to, setParams])

  const fetchLogs = async () => {
    setLoading(true)
    setError(null)
    try {
      const url = new URL('/admin/audit', window.location.origin)
      url.searchParams.set('page', String(page))
      url.searchParams.set('pageSize', String(pageSize))
      if (query) url.searchParams.set('q', query)
      if (action) url.searchParams.set('action', action)
      if (userId) url.searchParams.set('userId', userId)
      if (from) url.searchParams.set('from', from)
      if (to) url.searchParams.set('to', to)
      const r = await fetch(url.toString(), { credentials: 'include' })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      const json = await r.json()
      setData(json)
    } catch (e: any) {
      setError(e.message || 'Failed to load')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchLogs() }, [page, pageSize, query, action, userId, from, to])

  const pages = useMemo(() => Math.max(1, Math.ceil(data.total / data.pageSize)), [data])

  return (
    <div className="flex flex-col gap-4">
      <header className="flex items-center gap-3">
        <Shield className="text-muted-foreground" />
        <h1 className="text-xl font-semibold">Audit Logs</h1>
        <button onClick={fetchLogs} className="ml-auto inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-sm">
          <RefreshCcw className="h-4 w-4" /> Refresh
        </button>
      </header>

      <section className="rounded-lg border p-3 grid md:grid-cols-5 gap-2">
        <label className="flex items-center gap-2 border rounded-md px-2 py-1.5">
          <Search className="h-4 w-4" />
          <input aria-label="Search" className="flex-1 bg-transparent outline-none" placeholder="Search (action, IP, user agent, metadata)" value={query} onChange={e => setQuery(e.target.value)} />
        </label>
        <label className="flex items-center gap-2 border rounded-md px-2 py-1.5">
          <Filter className="h-4 w-4" />
          <input aria-label="Action filter" className="flex-1 bg-transparent outline-none" placeholder="Action (e.g., auth.login)" value={action} onChange={e => setAction(e.target.value)} />
        </label>
        <label className="flex items-center gap-2 border rounded-md px-2 py-1.5">
          <UsersIcon />
          <input aria-label="User ID filter" className="flex-1 bg-transparent outline-none" placeholder="User ID" value={userId} onChange={e => setUserId(e.target.value)} />
        </label>
        <label className="flex items-center gap-2 border rounded-md px-2 py-1.5">
          <Calendar className="h-4 w-4" />
          <input aria-label="From date/time" title="From" className="flex-1 bg-transparent outline-none" type="datetime-local" value={from} onChange={e => setFrom(e.target.value)} />
        </label>
        <label className="flex items-center gap-2 border rounded-md px-2 py-1.5">
          <Calendar className="h-4 w-4" />
          <input aria-label="To date/time" title="To" className="flex-1 bg-transparent outline-none" type="datetime-local" value={to} onChange={e => setTo(e.target.value)} />
        </label>
      </section>

      <section className="overflow-x-auto rounded-lg border">
        <table className="min-w-full text-sm">
          <thead className="bg-muted">
            <tr>
              <th className="text-left p-2">Time</th>
              <th className="text-left p-2">Action</th>
              <th className="text-left p-2">User</th>
              <th className="text-left p-2">IP</th>
              <th className="text-left p-2">Agent</th>
              <th className="text-left p-2">Metadata</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={6} className="p-3">Loading…</td></tr>
            )}
            {error && !loading && (
              <tr><td colSpan={6} className="p-3 text-red-600">{error}</td></tr>
            )}
            {!loading && !error && data.items.length === 0 && (
              <tr><td colSpan={6} className="p-3 opacity-70">No results</td></tr>
            )}
            {data.items.map(row => (
              <tr key={row.id} className="border-t">
                <td className="p-2 whitespace-nowrap">{new Date(row.createdAt).toLocaleString()}</td>
                <td className="p-2 font-mono text-xs">{row.action}</td>
                <td className="p-2">{row.userId || '—'}</td>
                <td className="p-2">{row.ipAddress || '—'}</td>
                <td className="p-2 truncate max-w-[240px]" title={row.userAgent || ''}>{row.userAgent || '—'}</td>
                <td className="p-2">
                  <pre className="max-h-16 overflow-auto text-xs whitespace-pre-wrap">{prettyMeta(row.metadata)}</pre>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <footer className="flex items-center gap-2">
        <span className="text-sm opacity-70">Page {data.page} of {pages}</span>
        <div className="ml-auto flex items-center gap-2">
          <button disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))} className="rounded-md border px-3 py-1.5 text-sm disabled:opacity-50">Prev</button>
          <button disabled={page >= pages} onClick={() => setPage(p => Math.min(pages, p + 1))} className="rounded-md border px-3 py-1.5 text-sm disabled:opacity-50">Next</button>
          <select aria-label="Page size" title="Page size" value={pageSize} onChange={e => { setPage(1); setPageSize(Number(e.target.value)) }} className="rounded-md border px-2 py-1.5 text-sm">
            {[10,25,50,100].map(n => <option key={n} value={n}>{n} / page</option>)}
          </select>
        </div>
      </footer>
    </div>
  )
}

function prettyMeta(meta: any) {
  try { return JSON.stringify(meta ?? null, null, 2) } catch { return String(meta) }
}

function UsersIcon() {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="h-4 w-4"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
  )
}
