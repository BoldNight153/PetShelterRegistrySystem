import { useAuth } from '@/lib/auth-context'
import { ShieldAlert } from 'lucide-react'
import * as React from 'react'

export default function AdminDocsChangelog() {
  const { user } = useAuth()
  const canSeeAdmin = !!user?.roles?.includes('system_admin')

  // hooks must be called unconditionally (rules-of-hooks). We declare state
  // and the effect here; the effect itself will early-return when the user
  // isn't allowed to see the admin docs.
  const [html, setHtml] = React.useState<string>('')
  const [error, setError] = React.useState<string | null>(null)
  function stringifyError(err: unknown) {
    if (!err) return String(err)
    if (err instanceof Error) return err.message
    try {
      return JSON.stringify(err)
    } catch {
      return String(err)
    }
  }

  React.useEffect(() => {
    if (!canSeeAdmin) return
    let mounted = true
    fetch('/admin/docs/api-changelog', { credentials: 'include' })
      .then(async (r) => {
        if (!r.ok) throw new Error('failed to load changelog')
        const text = await r.text()
        if (mounted) setHtml(text)
      })
      .catch((e) => { if (mounted) setError(stringifyError(e)) })
    return () => { mounted = false }
  }, [canSeeAdmin])

  if (!canSeeAdmin) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 text-red-600 dark:text-red-400"><ShieldAlert className="h-5 w-5" /> Access denied</div>
        <p className="text-sm text-muted-foreground mt-2">Please sign in to view documentation.</p>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-semibold">API Changelog</h1>
      {error && <p className="text-sm text-red-500">{error}</p>}
      <div className="prose prose-sm max-w-none dark:prose-invert" dangerouslySetInnerHTML={{ __html: html }} />
    </div>
  )
}
