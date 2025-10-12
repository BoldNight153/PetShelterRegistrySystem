import { useAuth } from '@/lib/auth-context'
import { ShieldAlert } from 'lucide-react'
import * as React from 'react'

export default function AdminDocsChangelog() {
  const { user } = useAuth()
  const canSeeAdmin = !!user?.roles?.includes('system_admin')
  if (!canSeeAdmin) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 text-red-600 dark:text-red-400"><ShieldAlert className="h-5 w-5" /> Access denied</div>
        <p className="text-sm text-muted-foreground mt-2">Please sign in to view documentation.</p>
      </div>
    )
  }
  const [html, setHtml] = React.useState<string>('')
  const [error, setError] = React.useState<string | null>(null)
  React.useEffect(() => {
    let mounted = true
    fetch('/admin/docs/api-changelog', { credentials: 'include' })
      .then(async (r) => {
        if (!r.ok) throw new Error('failed to load changelog')
        const text = await r.text()
        if (mounted) setHtml(text)
      })
      .catch((e) => { if (mounted) setError(String(e?.message || e)) })
    return () => { mounted = false }
  }, [])

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-semibold">API Changelog</h1>
      {error && <p className="text-sm text-red-500">{error}</p>}
      <div className="prose prose-sm max-w-none dark:prose-invert" dangerouslySetInnerHTML={{ __html: html }} />
    </div>
  )
}
