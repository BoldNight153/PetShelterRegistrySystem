import { useEffect, useState } from 'react'
import { loadMarkdown } from '@/docs/md'
import { MarkdownRenderer } from '@/components/docs/markdown-renderer'

export default function MarkdownView({ path }: { path: string }) {
  const [html, setHtml] = useState<string>('')
  const [error, setError] = useState<string>('')
  const [loading, setLoading] = useState<boolean>(true)

  useEffect(() => {
    let aborted = false
    const run = async () => {
      setLoading(true)
      setError('')
      try {
        const out = await loadMarkdown(path)
        if (!aborted) setHtml(out)
      } catch {
        if (!aborted) setError('Document not found or failed to load.')
      } finally {
        if (!aborted) setLoading(false)
      }
    }
    run()
    return () => { aborted = true }
  }, [path])

  if (loading) return <div className="px-6 py-8 text-sm opacity-70">Loading…</div>
  if (error) return <div className="px-6 py-8 text-sm text-red-600">{error}</div>
  return (
    <div className="px-6 py-8">
      <div className="prose dark:prose-invert max-w-3xl mx-auto">
        <MarkdownRenderer
          markdown={html}
          theme={{ light: 'github-light-high-contrast', dark: 'github-dark-high-contrast' }}
          defaultColor="light-dark()"
        />
      </div>
    </div>
  )
}
