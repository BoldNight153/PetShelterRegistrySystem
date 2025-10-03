import React, { Suspense, useEffect, useState } from 'react'

const RedocStandaloneLazy = React.lazy(() =>
  import('redoc').then((mod) => ({ default: mod.RedocStandalone }))
)

export default function RedocPage() {
  const [spec, setSpec] = useState<any | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    const url = '/api-docs/latest/openapi.json'
    setLoading(true)
    fetch(url)
      .then(async (res) => {
        if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`)
        const json = await res.json()
        if (!cancelled) setSpec(json)
      })
      .catch((err) => {
        if (!cancelled) setError(String(err))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (loading) return <div className="p-4 text-sm opacity-70">Loading API docs…</div>
  if (error)
    return (
      <div className="p-4">
        <h2 className="text-lg font-semibold">API docs are unavailable</h2>
        <p className="mt-2">Could not load API specification from the backend.</p>
        <pre className="mt-3 text-red-500 whitespace-pre-wrap text-xs">{error}</pre>
        <p className="mt-3 text-sm opacity-80">Make sure the backend is running on port 4000 and reload this page.</p>
      </div>
    )

  return (
    <div className="w-full min-h-[80vh] rounded-xl bg-card text-card-foreground">
      <Suspense fallback={<div className="p-4 text-sm opacity-70">Loading viewer…</div>}>
        <RedocStandaloneLazy spec={spec} />
      </Suspense>
    </div>
  )
}
