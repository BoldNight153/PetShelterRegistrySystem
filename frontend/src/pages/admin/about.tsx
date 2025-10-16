import { useEffect, useMemo, useState } from 'react';

declare const __APP_VERSION__: string;

type VersionInfo = {
  backend: { version: string; commit: string | null };
  openapi: { pets: string | null; auth: string | null; admin: string | null };
  timestamp: string;
};

export default function AdminAboutPage() {
  const [info, setInfo] = useState<VersionInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<'none' | 'root-readme' | 'backend-readme' | 'frontend-readme' | 'root-changelog' | 'backend-changelog' | 'frontend-changelog'>('none');
  const viteEnv = (import.meta as unknown as { env?: Record<string, string> }).env;
  const frontendVersion = (viteEnv?.VITE_APP_VERSION as string | undefined) || __APP_VERSION__;

  const docUrl = useMemo(() => {
    switch (view) {
      case 'root-readme': return '/admin/docs/readme/root?format=html';
      case 'backend-readme': return '/admin/docs/readme/backend?format=html';
      case 'frontend-readme': return '/admin/docs/readme/frontend?format=html';
      case 'root-changelog': return '/admin/docs/changelog/root?format=html';
      case 'backend-changelog': return '/admin/docs/changelog/backend?format=html';
      case 'frontend-changelog': return '/admin/docs/changelog/frontend?format=html';
      default: return null;
    }
  }, [view]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch('/admin/version', { credentials: 'include' });
        if (!res.ok) throw new Error(`Failed to load version info (${res.status})`);
        const data = await res.json();
        if (!cancelled) setInfo(data);
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to load version info';
        if (!cancelled) setError(msg);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-semibold">About / Version</h1>
      <p className="text-sm text-muted-foreground max-w-3xl">This page provides runtime version info and quick links to documentation, READMEs, and changelogs. Admins can also preview markdown files inline.</p>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <section className="rounded border p-4">
          <h2 className="text-lg font-medium mb-2">Frontend</h2>
          <dl className="space-y-1">
            <div className="flex gap-2"><dt className="w-40 text-muted-foreground">App version</dt><dd className="font-mono">{String(frontendVersion)}</dd></div>
          </dl>
          <div className="mt-3 flex flex-wrap gap-2 text-sm">
            <a className="underline" href="/" target="_self">Open app</a>
            <a className="underline" href="/docs" target="_self">API Docs (latest)</a>
            <button className="underline" onClick={() => setView('frontend-readme')}>Frontend README</button>
            <button className="underline" onClick={() => setView('frontend-changelog')}>Frontend CHANGELOG</button>
          </div>
        </section>
        <section className="rounded border p-4">
          <h2 className="text-lg font-medium mb-2">Backend</h2>
          {error ? (
            <p className="text-red-600">{error}</p>
          ) : !info ? (
            <p className="text-muted-foreground">Loading…</p>
          ) : (
            <dl className="space-y-1">
              <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Version</dt><dd className="font-mono">{info.backend.version}</dd></div>
              <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Commit</dt><dd className="font-mono">{info.backend.commit || '—'}</dd></div>
              <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Reported at</dt><dd>{new Date(info.timestamp).toLocaleString()}</dd></div>
            </dl>
          )}
          <div className="mt-3 flex flex-wrap gap-2 text-sm">
            <a className="underline" href="/api-docs" target="_self">Pets API docs</a>
            <a className="underline" href="/auth-docs" target="_self">Auth API docs</a>
            <a className="underline" href="/api-docs/admin" target="_self">Admin API docs</a>
            <button className="underline" onClick={() => setView('backend-readme')}>Backend README</button>
            <button className="underline" onClick={() => setView('backend-changelog')}>Backend CHANGELOG</button>
          </div>
        </section>
      </div>
      <section className="rounded border p-4">
        <h2 className="text-lg font-medium mb-2">OpenAPI Specs</h2>
        {info ? (
          <dl className="space-y-1">
            <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Pets API</dt><dd className="font-mono">{info.openapi.pets ?? '—'}</dd></div>
            <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Auth API</dt><dd className="font-mono">{info.openapi.auth ?? '—'}</dd></div>
            <div className="flex gap-2"><dt className="w-40 text-muted-foreground">Admin API</dt><dd className="font-mono">{info.openapi.admin ?? '—'}</dd></div>
          </dl>
        ) : (
          <p className="text-muted-foreground">Loading…</p>
        )}
      </section>
      <section className="rounded border p-4">
        <h2 className="text-lg font-medium mb-2">Project Docs</h2>
        <div className="flex flex-wrap gap-2 text-sm mb-3">
          <button className={`underline ${view === 'root-readme' ? 'font-semibold' : ''}`} onClick={() => setView('root-readme')}>Root README</button>
          <button className={`underline ${view === 'backend-readme' ? 'font-semibold' : ''}`} onClick={() => setView('backend-readme')}>Backend README</button>
          <button className={`underline ${view === 'frontend-readme' ? 'font-semibold' : ''}`} onClick={() => setView('frontend-readme')}>Frontend README</button>
          <button className={`underline ${view === 'root-changelog' ? 'font-semibold' : ''}`} onClick={() => setView('root-changelog')}>Root CHANGELOG</button>
          <button className={`underline ${view === 'backend-changelog' ? 'font-semibold' : ''}`} onClick={() => setView('backend-changelog')}>Backend CHANGELOG</button>
          <button className={`underline ${view === 'frontend-changelog' ? 'font-semibold' : ''}`} onClick={() => setView('frontend-changelog')}>Frontend CHANGELOG</button>
        </div>
        {docUrl ? (
          <div className="border rounded overflow-hidden h-[60vh]">
            <iframe title="Doc preview" src={docUrl} className="w-full h-full" />
          </div>
        ) : (
          <p className="text-muted-foreground">Select a document to preview it here.</p>
        )}
      </section>
    </div>
  );
}
