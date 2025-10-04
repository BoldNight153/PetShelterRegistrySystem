import React, { Suspense, useEffect, useMemo, useState } from 'react'

const RedocStandaloneLazy = React.lazy(() =>
  import('redoc').then((mod) => ({ default: mod.RedocStandalone }))
)

export default function RedocPage() {
  // Detect light/dark mode and update on changes
  type ThemeMode = 'light' | 'dark'
  const getMode = (): ThemeMode =>
    typeof document !== 'undefined' && document.documentElement.classList.contains('dark')
      ? 'dark'
      : (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
          ? 'dark'
          : 'light')

  const [mode, setMode] = useState<ThemeMode>(getMode())

  useEffect(() => {
    const html = document.documentElement
    const mo = new MutationObserver(() => setMode(getMode()))
    mo.observe(html, { attributes: true, attributeFilter: ['class'] })
    const mql = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = () => setMode(getMode())
    if (mql.addEventListener) mql.addEventListener('change', onChange)
    else mql.addListener(onChange)
    return () => {
      mo.disconnect()
      if (mql.removeEventListener) mql.removeEventListener('change', onChange)
      else mql.removeListener(onChange)
    }
  }, [])

  // Curated hex palettes for ReDoc (no CSS vars)
  const buildRedocTheme = (m: ThemeMode) => {
    const light = {
      colors: {
        primary: { main: '#4F46E5' }, // indigo-600
        text: { primary: '#0B1220', secondary: '#374151' },
        http: {
          get: '#10B981', post: '#3B82F6', put: '#F59E0B', delete: '#EF4444',
          options: '#06B6D4', patch: '#8B5CF6', basic: '#64748B', link: '#0EA5E9', head: '#A3A3A3',
        },
        border: { dark: '#E5E7EB' }, // gray-200
        background: { default: '#FFFFFF', alternative: '#F7FAFC' },
      },
      typography: {
        fontSize: '15px',
        lineHeight: '1.65',
        fontFamily:
          'Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica Neue, Arial, "Apple Color Emoji", "Segoe UI Emoji"',
        code: {
          fontFamily:
            'JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", ui-monospace, monospace',
          fontSize: '13.5px',
        },
        links: {
          color: '#4F46E5',
          hover: '#4338CA',
          visited: '#6D28D9',
        },
      },
      sidebar: {
        backgroundColor: '#F8FAFC',
        textColor: '#0F172A',
        width: '280px',
      },
      rightPanel: {
        backgroundColor: '#FFFFFF',
        textColor: '#0B1220',
        width: '40%',
      },
      codeBlock: {
        backgroundColor: '#F3F4F6', // gray-100
        textColor: '#111827',
        tokens: {},
      },
    }
    const dark = {
      colors: {
        primary: { main: '#93C5FD' }, // blue-300 for clarity on dark
        text: { primary: '#E6E8EB', secondary: '#B3BDC9' },
        http: {
          get: '#34D399', post: '#60A5FA', put: '#FBBF24', delete: '#F87171',
          options: '#22D3EE', patch: '#A78BFA', basic: '#94A3B8', link: '#38BDF8', head: '#A3A3A3',
        },
        border: { dark: '#273244' }, // slightly lighter than pure
        background: { default: '#0B1220', alternative: '#0F172A' },
      },
      typography: {
        fontSize: '15px',
        lineHeight: '1.65',
        fontFamily:
          'Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, Helvetica Neue, Arial, "Apple Color Emoji", "Segoe UI Emoji"',
        code: {
          fontFamily:
            'JetBrains Mono, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", ui-monospace, monospace',
          fontSize: '13.5px',
        },
        links: {
          color: '#93C5FD',
          hover: '#60A5FA',
          visited: '#A78BFA',
        },
      },
      sidebar: {
        backgroundColor: '#0F172A',
        textColor: '#E6E8EB',
        width: '280px',
      },
      rightPanel: {
        backgroundColor: '#0B1220',
        textColor: '#E6E8EB',
        width: '40%',
      },
      codeBlock: {
        backgroundColor: '#0A1020',
        textColor: '#E6E8EB',
        tokens: {},
      },
    }
    return m === 'dark' ? dark : light
  }

  const redocTheme = useMemo(() => buildRedocTheme(mode), [mode])
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
  // IMPORTANT: All hooks must run before any early returns to keep hook order stable
  const dynamicCss = useMemo(() => {
    const isDark = mode === 'dark'
    const heading = isDark ? '#E6E8EB' : '#0B1220'
    const headingAccent = isDark ? '#93C5FD' : '#4F46E5'
    const contentBg = isDark ? '#0B1220' : '#FFFFFF'
    const contentText = isDark ? '#E6E8EB' : '#0B1220'
    const mutedText = isDark ? '#B3BDC9' : '#374151'
    const link = isDark ? '#93C5FD' : '#4F46E5'
    const linkHover = isDark ? '#60A5FA' : '#4338CA'
    const rightBg = contentBg
    const rightText = contentText
    const rightBorder = isDark ? '#334155' : '#E5E7EB'
    const codeBg = isDark ? '#0A1020' : '#F3F4F6'
    const codeText = isDark ? '#E6E8EB' : '#111827'
    const rowAltBg = isDark ? '#0E1525' : '#FAFAFA'
    const tableHeaderBg = isDark ? '#111827' : '#F3F4F6'
    const tableHeaderText = isDark ? '#E6E8EB' : '#111827'
    const tabBorder = rightBorder
    const selectedTab = isDark ? '#93C5FD' : '#4F46E5'
    const inlineCodeBg = isDark ? '#111827' : '#F3F4F6'
    const inlineCodeText = isDark ? '#E5E7EB' : '#111827'
    const blockquoteBorder = rightBorder
    const focusRing = isDark ? '#60A5FA' : '#2563EB'
    const requiredColor = isDark ? '#F87171' : '#EF4444'
    const deprecatedColor = isDark ? '#FBBF24' : '#D97706'
  /* Syntax token colors */
  const tokComment = isDark ? '#7A869A' : '#6B7280'
  const tokKeyword = isDark ? '#93C5FD' : '#1D4ED8'
  const tokString = isDark ? '#34D399' : '#047857'
  const tokNumber = isDark ? '#FBBF24' : '#B45309'
  const tokFunction = isDark ? '#A78BFA' : '#6D28D9'
  const tokPunctuation = isDark ? '#9AA4B2' : '#6B7280'
    return `
      /* Base content colors */
      .rd-theme { background: ${contentBg} !important; color: ${contentText} !important; }
      .rd-theme p, .rd-theme li, .rd-theme dt, .rd-theme dd { color: ${contentText} !important; }
      .rd-theme small, .rd-theme .hint, .rd-theme .description { color: ${mutedText} !important; }

      /* Headings like "Response Schema" */
      .rd-theme h5 { color: ${heading} !important; font-weight: 600 !important; letter-spacing: 0.01em; }
      .rd-theme h5 span { color: ${headingAccent} !important; font-weight: 500; }

      /* Links */
      .rd-theme a { color: ${link} !important; text-decoration: none; text-underline-offset: 2px; }
      .rd-theme a:hover { color: ${linkHover} !important; text-decoration: underline; }

      /* Right panel (responses/samples) */
      .rd-theme aside,
      .rd-theme [class*='right-panel'],
      .rd-theme [class*='RightPanel'] { background: ${rightBg} !important; color: ${rightText} !important; }
      .rd-theme aside *,
      .rd-theme [class*='right-panel'] *,
      .rd-theme [class*='RightPanel'] * { color: ${rightText} !important; }
      .rd-theme aside hr { border-color: ${rightBorder} !important; }
      .rd-theme aside input,
      .rd-theme aside select,
      .rd-theme aside .example,
      .rd-theme aside pre,
      .rd-theme aside code { background: ${codeBg} !important; color: ${codeText} !important; border-color: ${rightBorder} !important; }

  /* Main content code blocks */
  .rd-theme pre { background: ${codeBg} !important; color: ${codeText} !important; border: 1px solid ${rightBorder} !important; border-radius: 8px; padding: 12px 14px; overflow: auto; }
  .rd-theme pre code { background: transparent !important; color: ${codeText} !important; font-variant-ligatures: none; -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility; line-height: 1.55; font-size: 13.5px; tab-size: 2; }
  .rd-theme :not(pre) > code { background: ${inlineCodeBg} !important; color: ${inlineCodeText} !important; border: 1px solid ${rightBorder} !important; padding: 0.125rem 0.25rem; border-radius: 0.25rem; font-variant-ligatures: none; -webkit-font-smoothing: antialiased; }
  /* Syntax highlighting (Prism-based) */
  .rd-theme pre code .token.comment,
  .rd-theme pre code .token.prolog,
  .rd-theme pre code .token.doctype,
  .rd-theme pre code .token.cdata { color: ${tokComment} !important; }
  .rd-theme pre code .token.punctuation { color: ${tokPunctuation} !important; }
  .rd-theme pre code .token.boolean,
  .rd-theme pre code .token.number { color: ${tokNumber} !important; }
  .rd-theme pre code .token.keyword { color: ${tokKeyword} !important; }
  .rd-theme pre code .token.function { color: ${tokFunction} !important; }
  .rd-theme pre code .token.string { color: ${tokString} !important; }

      /* Tables in content */
      .rd-theme table, .rd-theme th, .rd-theme td { border-color: ${rightBorder} !important; }
      .rd-theme th { background: ${tableHeaderBg} !important; color: ${tableHeaderText} !important; }
      .rd-theme tr:nth-child(even) td { background: ${rowAltBg} !important; }

      /* Tabs (e.g., request/response samples) */
      .rd-theme [role='tablist'] { border-bottom: 1px solid ${tabBorder} !important; }
      .rd-theme [role='tab'] { color: ${mutedText} !important; }
      .rd-theme [role='tab'][aria-selected='true'] {
        color: ${contentText} !important;
        font-weight: 600 !important;
        border-bottom: 2px solid ${selectedTab} !important;
        background: ${isDark ? '#0F172A' : '#EEF2FF'} !important;
      }
      /* Compatibility with alternative tab implementations */
      .rd-theme .react-tabs__tab--selected,
      .rd-theme [class*='Tabs'] [aria-selected='true'] {
        color: ${contentText} !important;
        font-weight: 600 !important;
        border-bottom-color: ${selectedTab} !important;
        background: ${isDark ? '#0F172A' : '#EEF2FF'} !important;
      }

      /* Blockquotes and dividers */
      .rd-theme blockquote { border-left: 3px solid ${blockquoteBorder} !important; color: ${mutedText} !important; }
      .rd-theme hr { border-color: ${rightBorder} !important; }

      /* Forms (search/params) */
      .rd-theme input, .rd-theme select, .rd-theme textarea { background: ${isDark ? '#0F172A' : '#FFFFFF'} !important; color: ${contentText} !important; border: 1px solid ${rightBorder} !important; }
      .rd-theme input::placeholder, .rd-theme textarea::placeholder { color: ${mutedText} !important; opacity: 1 !important; }

      /* Badges and hints */
      .rd-theme .required { color: ${requiredColor} !important; font-weight: 600 !important; }
      .rd-theme .deprecated { color: ${deprecatedColor} !important; font-weight: 600 !important; }

      /* Sidebar/Navigation inside ReDoc (if visible) */
      .rd-theme nav a { color: ${contentText} !important; }
      .rd-theme nav a[aria-current='page'], .rd-theme nav a.active { color: ${selectedTab} !important; font-weight: 600 !important; }

      /* Focus styles for accessibility */
      .rd-theme a:focus-visible, .rd-theme button:focus-visible, .rd-theme [role='tab']:focus-visible, .rd-theme input:focus-visible, .rd-theme select:focus-visible, .rd-theme textarea:focus-visible { outline: 2px solid ${focusRing} !important; outline-offset: 2px !important; border-color: ${focusRing} !important; }
    `
  }, [mode])

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
    <div className="rd-theme w-full min-h-[80vh] rounded-xl">
      <Suspense fallback={<div className="p-4 text-sm opacity-70">Loading viewer…</div>}>
        <RedocStandaloneLazy
          key={`redoc-${mode}`}
          spec={spec}
          options={{
            theme: redocTheme as any,
            scrollYOffset: 0,
            hideDownloadButton: false,
          }}
        />
      </Suspense>
      <style dangerouslySetInnerHTML={{ __html: dynamicCss }} />
    </div>
  )
}
