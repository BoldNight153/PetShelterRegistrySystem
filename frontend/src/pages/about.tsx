import { useEffect, useState } from 'react'
import { useAuth } from '@/lib/auth-context'

declare const __APP_VERSION__: string

type VersionInfo = {
  backend: { version: string; commit: string | null }
  openapi: { pets: string | null; auth: string | null; admin: string | null }
  timestamp: string
}

export default function AboutPage() {
  const [info, setInfo] = useState<VersionInfo | null>(null)
  const [error, setError] = useState<string | null>(null)
  const { authenticated } = useAuth()
  const viteEnv = (import.meta as unknown as { env?: Record<string, string> }).env
  const frontendVersion = (viteEnv?.VITE_APP_VERSION as string | undefined) || __APP_VERSION__

  useEffect(() => {
    if (!authenticated) {
      setInfo(null)
      setError(null)
      return
    }
    let cancelled = false
    ;(async () => {
      try {
        const res = await fetch('/admin/version', { credentials: 'include' })
        if (!res.ok) throw new Error(`Failed to load version info (${res.status})`)
        const data = await res.json()
        if (!cancelled) setInfo(data)
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to load version info'
        if (!cancelled) setError(msg)
      }
    })()
    return () => { cancelled = true }
  }, [authenticated])

  return (
    <div className="p-6 space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold">About Pet Shelter Registry System</h1>
        <p className="text-muted-foreground max-w-3xl">
          A full-stack reference app with secure authentication, role-based access control, and comprehensive API documentation. Explore the APIs, read the docs, and check out recent changes below.
        </p>
      </header>

      <section className="rounded border p-4">
        <h2 className="text-lg font-medium mb-2">Versions</h2>
        <dl className="space-y-1">
          <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Frontend</dt><dd className="font-mono">{String(frontendVersion)}</dd></div>
          {!authenticated ? (
            <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Backend</dt><dd className="text-muted-foreground">Sign in to view backend version details.</dd></div>
          ) : error ? (
            <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Backend</dt><dd className="text-red-600">{error}</dd></div>
          ) : info ? (
            <>
              <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Backend</dt><dd className="font-mono">{info.backend.version}</dd></div>
              <div className="flex gap-2"><dt className="w-40 text-muted-foreground">OpenAPI (Pets)</dt><dd className="font-mono">{info.openapi.pets ?? '—'}</dd></div>
              <div className="flex gap-2"><dt className="w-40 text-muted-foreground">OpenAPI (Auth)</dt><dd className="font-mono">{info.openapi.auth ?? '—'}</dd></div>
              <div className="flex gap-2"><dt className="w-40 text-muted-foreground">OpenAPI (Admin)</dt><dd className="font-mono">{info.openapi.admin ?? '—'}</dd></div>
            </>
          ) : (
            <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Backend</dt><dd className="text-muted-foreground">Loading…</dd></div>
          )}
        </dl>
      </section>

      <section className="rounded border p-4">
        <h2 className="text-lg font-medium mb-2">Quick Links</h2>
        <ul className="list-disc pl-5 space-y-1">
          <li><a className="underline" href="https://github.com/BoldNight153/PetShelterRegistrySystem" target="_blank" rel="noreferrer noopener">GitHub repo</a></li>
        </ul>
        <p className="text-xs text-muted-foreground mt-2">API documentation is available to system administrators in the Admin area.</p>
      </section>
      
      <section className="rounded border p-4">
        <h2 className="text-lg font-medium mb-2">Documentation</h2>
        <p className="text-sm text-muted-foreground">For security, full API docs and project READMEs/CHANGELOGs are available in the Admin About page for authorized users.</p>
      </section>
    </div>
  )
}
