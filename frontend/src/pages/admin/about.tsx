import { useEffect, useState } from 'react';

declare const __APP_VERSION__: string;

type VersionInfo = {
  backend: { version: string; commit: string | null };
  openapi: { pets: string | null; auth: string | null; admin: string | null };
  timestamp: string;
};

export default function AdminAboutPage() {
  const [info, setInfo] = useState<VersionInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const viteEnv = (import.meta as unknown as { env?: Record<string, string> }).env;
  const frontendVersion = (viteEnv?.VITE_APP_VERSION as string | undefined) || __APP_VERSION__;

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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <section className="rounded border p-4">
          <h2 className="text-lg font-medium mb-2">Frontend</h2>
          <dl className="space-y-1">
            <div className="flex gap-2"><dt className="w-40 text-muted-foreground">App version</dt><dd className="font-mono">{String(frontendVersion)}</dd></div>
          </dl>
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
    </div>
  );
}
