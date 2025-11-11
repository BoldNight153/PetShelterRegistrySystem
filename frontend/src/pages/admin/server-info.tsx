import { useAuth } from '@/lib/auth-context'
import { ShieldAlert } from 'lucide-react'

export default function ServerInfoPlaceholder() {
  const { user } = useAuth()
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
    <div className="p-6 space-y-4">
      <h1 className="text-2xl font-semibold">Server Info</h1>
      <p className="text-muted-foreground">This section will provide health and monitoring dashboards. Coming soon.</p>
      <ul className="list-disc pl-6 text-sm text-muted-foreground">
        <li>Uptime, CPU, memory, event loop lag</li>
        <li>DB health and Prisma metrics</li>
        <li>Request rates and error rates</li>
        <li>Background job status</li>
      </ul>
      <div className="rounded border p-4">
        <p className="text-sm">While under development, you can check API health at <code>/health</code> and auth diagnostics at <code>/auth/mode</code>.</p>
  <p className="text-sm mt-2">Preview charts: <a className="underline" href="/server-info/charts">Server Info Charts</a></p>
      </div>
    </div>
  )
}
