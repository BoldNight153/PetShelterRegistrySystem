import React, { useEffect, useState } from 'react';
import { RedocStandalone } from 'redoc';

export default function RedocPage(): JSX.Element {
  const [spec, setSpec] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const url = '/api/api-docs/latest/openapi.json';
    let cancelled = false;
    setLoading(true);
    fetch(url)
      .then(async res => {
        if (!res.ok) throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
        const json = await res.json();
        if (!cancelled) setSpec(json);
      })
      .catch(err => {
        if (!cancelled) setError(String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (loading) {
    return <div style={{ padding: 24 }}>Loading API docs…</div>;
  }

  if (error) {
    return (
      <div style={{ padding: 24 }}>
        <h2>API docs are unavailable</h2>
        <p>Could not load API specification from the backend.</p>
        <pre style={{ whiteSpace: 'pre-wrap', color: 'crimson' }}>{error}</pre>
        <p>Make sure the backend is running (port 4000) and reload this page.</p>
      </div>
    );
  }

  return (
    <div style={{ height: '100vh' }}>
      {/* Pass the parsed spec to RedocStandalone so we don't rely on the
          runtime bundle fetching the spec itself. This makes failures easier
          to detect and surfaces a helpful message when the backend is down. */}
      <RedocStandalone spec={spec} />
    </div>
  );
}
