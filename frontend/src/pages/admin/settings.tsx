import { useAuth } from '@/lib/auth-context'
import { useEffect, useState } from 'react'
import { loadSettings, saveSettings } from '@/lib/api'
import { ShieldAlert } from 'lucide-react'

export default function AdminSettingsPage() {
  const { user } = useAuth()
  const isSystemAdmin = !!user?.roles?.includes('system_admin')
  const sections = [
    { id: 'general', label: 'General' },
    { id: 'monitoring', label: 'Monitoring' },
    { id: 'auth', label: 'Authentication' },
    { id: 'docs', label: 'Documentation' },
    { id: 'security', label: 'Security' },
  ]

  // Local state mirrors of settings values
  const [, setLoading] = useState(true)
  const [saving, setSaving] = useState<string | null>(null)
  const [general, setGeneral] = useState({ appName: 'Pet Shelter Registry', supportEmail: '' })
  const [monitoring, setMonitoring] = useState({ chartsRefreshSec: 15, retentionDays: 7 })
  const [auth, setAuthSettings] = useState({ mode: 'session' as 'session' | 'jwt', google: false, github: false })
  const [docs, setDocs] = useState({ showPublicDocsLink: true })
  const [security, setSecurity] = useState({ sessionMaxAgeMin: 60, requireEmailVerification: true })

  useEffect(() => {
    let cancel = false
    ;(async () => {
      try {
        const s = await loadSettings()
        if (cancel) return
        if (s.general) setGeneral({
          appName: String(s.general.appName ?? 'Pet Shelter Registry'),
          supportEmail: String(s.general.supportEmail ?? '')
        })
        if (s.monitoring) setMonitoring({
          chartsRefreshSec: Number(s.monitoring.chartsRefreshSec ?? 15),
          retentionDays: Number(s.monitoring.retentionDays ?? 7)
        })
        if (s.auth) setAuthSettings({
          mode: (s.auth.mode === 'jwt' ? 'jwt' : 'session'),
          google: Boolean(s.auth.google),
          github: Boolean(s.auth.github)
        })
        if (s.docs) setDocs({ showPublicDocsLink: Boolean(s.docs.showPublicDocsLink ?? true) })
        if (s.security) setSecurity({
          sessionMaxAgeMin: Number(s.security.sessionMaxAgeMin ?? 60),
          requireEmailVerification: Boolean(s.security.requireEmailVerification ?? true)
        })
      } finally {
        if (!cancel) setLoading(false)
      }
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

  async function saveCategory(id: string) {
    try {
      setSaving(id)
      if (id === 'general') await saveSettings('general', [
        { key: 'appName', value: general.appName },
        { key: 'supportEmail', value: general.supportEmail },
      ])
      if (id === 'monitoring') await saveSettings('monitoring', [
        { key: 'chartsRefreshSec', value: Number(monitoring.chartsRefreshSec) },
        { key: 'retentionDays', value: Number(monitoring.retentionDays) },
      ])
      if (id === 'auth') await saveSettings('auth', [
        { key: 'mode', value: auth.mode },
        { key: 'google', value: auth.google },
        { key: 'github', value: auth.github },
      ])
      if (id === 'docs') await saveSettings('docs', [
        { key: 'showPublicDocsLink', value: docs.showPublicDocsLink },
      ])
      if (id === 'security') await saveSettings('security', [
        { key: 'sessionMaxAgeMin', value: Number(security.sessionMaxAgeMin) },
        { key: 'requireEmailVerification', value: Boolean(security.requireEmailVerification) },
      ])
    } finally {
      setSaving(null)
    }
  }

  return (
    <div className="p-6">
      <div className="flex flex-col md:flex-row gap-6">
        {/* Main content */}
        <div className="flex-1 space-y-8">
          <div>
            <h1 className="text-2xl font-semibold">Admin Settings</h1>
            <p className="text-sm text-muted-foreground mt-1">Configure platform-wide administrative options.
            </p>
          </div>

          {/* General */}
          <section id="general" className="scroll-mt-20 space-y-4">
            <h2 className="text-lg font-medium">General</h2>
            <div className="rounded border p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium">App display name</label>
                <input className="mt-1 w-full rounded-md border px-3 py-2 bg-background" placeholder="Pet Shelter Registry" value={general.appName} onChange={e => setGeneral({ ...general, appName: e.target.value })} />
              </div>
              <div>
                <label className="block text-sm font-medium">Support email</label>
                <input className="mt-1 w-full rounded-md border px-3 py-2 bg-background" placeholder="support@example.com" value={general.supportEmail} onChange={e => setGeneral({ ...general, supportEmail: e.target.value })} />
              </div>
              <div className="pt-2"><button disabled={saving==='general'} onClick={() => saveCategory('general')} className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">{saving==='general' ? 'Saving…' : 'Save General'}</button></div>
            </div>
          </section>

          {/* Monitoring */}
          <section id="monitoring" className="scroll-mt-20 space-y-4">
            <h2 className="text-lg font-medium">Monitoring</h2>
            <div className="rounded border p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium">Charts refresh interval (seconds)</label>
                <input type="number" min={5} step={5} className="mt-1 w-40 rounded-md border px-3 py-2 bg-background" placeholder="15" value={monitoring.chartsRefreshSec} onChange={e => setMonitoring({ ...monitoring, chartsRefreshSec: Number(e.target.value) })} />
                <p className="text-xs text-muted-foreground mt-1">How often the admin charts auto-refresh.</p>
              </div>
              <div>
                <label className="block text-sm font-medium">Time series retention (days)</label>
                <input type="number" min={1} step={1} className="mt-1 w-40 rounded-md border px-3 py-2 bg-background" placeholder="7" value={monitoring.retentionDays} onChange={e => setMonitoring({ ...monitoring, retentionDays: Number(e.target.value) })} />
                <p className="text-xs text-muted-foreground mt-1">Retention period for MetricPoint records.</p>
              </div>
              <div className="pt-2"><button disabled={saving==='monitoring'} onClick={() => saveCategory('monitoring')} className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">{saving==='monitoring' ? 'Saving…' : 'Save Monitoring'}</button></div>
            </div>
          </section>

          {/* Authentication */}
          <section id="auth" className="scroll-mt-20 space-y-4">
            <h2 className="text-lg font-medium">Authentication</h2>
            <div className="rounded border p-4 space-y-4">
              <div>
                <label htmlFor="auth-mode" className="block text-sm font-medium">Auth mode</label>
                <select id="auth-mode" aria-label="Authentication mode" className="mt-1 w-60 rounded-md border px-3 py-2 bg-background" value={auth.mode} onChange={e => setAuthSettings({ ...auth, mode: (e.target.value as 'session' | 'jwt') })}>
                  <option value="session">session</option>
                  <option value="jwt">jwt</option>
                </select>
                <p className="text-xs text-muted-foreground mt-1">Switch between server sessions and stateless JWT cookies.</p>
              </div>
              <div>
                <label className="block text-sm font-medium">OAuth providers</label>
                <div className="mt-1 grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <label className="flex items-center gap-2 text-sm"><input type="checkbox" className="accent-foreground" checked={auth.google} onChange={e => setAuthSettings({ ...auth, google: e.target.checked })} /> Google</label>
                  <label className="flex items-center gap-2 text-sm"><input type="checkbox" className="accent-foreground" checked={auth.github} onChange={e => setAuthSettings({ ...auth, github: e.target.checked })} /> GitHub</label>
                </div>
                <p className="text-xs text-muted-foreground mt-1">Enable only providers with valid credentials configured.</p>
              </div>
              <div className="pt-2"><button disabled={saving==='auth'} onClick={() => saveCategory('auth')} className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">{saving==='auth' ? 'Saving…' : 'Save Authentication'}</button></div>
            </div>
          </section>

          {/* Documentation */}
          <section id="docs" className="scroll-mt-20 space-y-4">
            <h2 className="text-lg font-medium">Documentation</h2>
            <div className="rounded border p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium">Expose public Docs link</label>
                <label className="mt-1 inline-flex items-center gap-2 text-sm"><input type="checkbox" className="accent-foreground" checked={docs.showPublicDocsLink} onChange={e => setDocs({ ...docs, showPublicDocsLink: e.target.checked })} /> Show Pets REST API in sidebar</label>
              </div>
              <div className="pt-2"><button disabled={saving==='docs'} onClick={() => saveCategory('docs')} className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">{saving==='docs' ? 'Saving…' : 'Save Documentation'}</button></div>
            </div>
          </section>

          {/* Security */}
          <section id="security" className="scroll-mt-20 space-y-4">
            <h2 className="text-lg font-medium">Security</h2>
            <div className="rounded border p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium">Session max age (minutes)</label>
                <input type="number" min={5} step={5} className="mt-1 w-40 rounded-md border px-3 py-2 bg-background" placeholder="60" value={security.sessionMaxAgeMin} onChange={e => setSecurity({ ...security, sessionMaxAgeMin: Number(e.target.value) })} />
              </div>
              <div>
                <label className="block text-sm font-medium">Require email verification</label>
                <label className="mt-1 inline-flex items-center gap-2 text-sm"><input type="checkbox" className="accent-foreground" checked={security.requireEmailVerification} onChange={e => setSecurity({ ...security, requireEmailVerification: e.target.checked })} /> Enforce verification before login</label>
              </div>
              <div className="pt-2"><button disabled={saving==='security'} onClick={() => saveCategory('security')} className="px-3 py-1.5 rounded bg-primary text-primary-foreground text-sm">{saving==='security' ? 'Saving…' : 'Save Security'}</button></div>
            </div>
          </section>
        </div>

        {/* Right rail navigation */}
        <aside className="w-full md:w-64 md:sticky md:top-4 h-fit">
          <nav className="rounded border p-3">
            <div className="text-xs uppercase text-muted-foreground px-1 mb-2">Settings</div>
            <ul className="space-y-1">
              {sections.map(s => (
                <li key={s.id}>
                  <a className="block rounded px-2 py-1 hover:bg-accent" href={`#${s.id}`}>{s.label}</a>
                </li>
              ))}
            </ul>
          </nav>
        </aside>
      </div>
    </div>
  )
}
