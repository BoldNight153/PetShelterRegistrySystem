import { useEffect, useState } from 'react'
import { useAuth } from '@/lib/auth-context'
import { ShieldAlert } from 'lucide-react'

export default function ServerDashboard() {
  const { user } = useAuth()
  const isSystemAdmin = !!user?.roles?.includes('system_admin')
  const [health, setHealth] = useState<any>(null)
  const [runtime, setRuntime] = useState<any>(null)

  useEffect(() => {
    let cancel = false
    ;(async () => {
      try {
        const h = await fetch('/health', { credentials: 'include' }).then(r => r.ok ? r.json() : null)
        const rt = await fetch('/admin/monitoring/runtime', { credentials: 'include' }).then(r => r.ok ? r.json() : null)
        if (!cancel) { setHealth(h); setRuntime(rt) }
      } catch {}
    })()
    return () => { cancel = true }
  }, [])

  if (!isSystemAdmin) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 text-red-600 dark:text-red-400"><ShieldAlert className="h-5 w-5" /> Access denied</div>
        <p className="text-sm text-muted-foreground mt-2">This page is restricted to system administrators.</p>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Server Dashboard</h1>
        <p className="text-muted-foreground">Quick health and runtime snapshot.</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded border p-4">
          <div className="text-sm text-muted-foreground">Health</div>
          <div className="text-2xl font-semibold">{health?.status ?? '—'}</div>
        </div>
        <div className="rounded border p-4">
          <div className="text-sm text-muted-foreground">Node</div>
          <div className="text-2xl font-semibold">{runtime?.node ?? '—'}</div>
        </div>
        <div className="rounded border p-4">
          <div className="text-sm text-muted-foreground">Uptime (s)</div>
          <div className="text-2xl font-semibold">{runtime?.uptimeSec ? Math.floor(runtime.uptimeSec) : '—'}</div>
        </div>
      </div>
      <div className="rounded border p-4">
        <h2 className="font-medium mb-2">Process memory</h2>
        <pre className="text-xs overflow-auto">{JSON.stringify(runtime?.memory, null, 2) || '—'}</pre>
      </div>
    </div>
  )
}
