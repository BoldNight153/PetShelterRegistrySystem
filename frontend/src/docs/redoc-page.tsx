import React, { Suspense, useCallback, useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'

const RedocStandaloneLazy = React.lazy(() =>
  import('redoc').then((mod) => ({ default: mod.RedocStandalone }))
)

export default function RedocPage() {
  type Spec = 'pets' | 'auth' | 'admin'
  // Detect light/dark mode and update on changes
  type ThemeMode = 'light' | 'dark'
  const getMode = useCallback((): ThemeMode => {
    if (typeof document === 'undefined') return 'light'
    const html = document.documentElement
    const dataTheme = (html.getAttribute('data-theme') || '').toLowerCase()
    if (dataTheme === 'dark') return 'dark'
    if (dataTheme === 'light') return 'light'
    try {
      const stored = (localStorage.getItem('theme') || '').toLowerCase()
      if (stored === 'dark') return 'dark'
      if (stored === 'light') return 'light'
  } catch { /* ignore theme storage */ }
    if (html.classList.contains('dark')) return 'dark'
    if (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark'
    return 'light'
  }, [])

  const [mode, setMode] = useState<ThemeMode>(getMode())

  useEffect(() => {
    const html = document.documentElement
    const onChange = () => setMode(getMode())
    const mo = new MutationObserver(onChange)
  mo.observe(html, { attributes: true, attributeFilter: ['class', 'data-theme'] })
    const mql = window.matchMedia('(prefers-color-scheme: dark)')
    if (mql.addEventListener) mql.addEventListener('change', onChange)
    else mql.addListener(onChange)
    // Listen for explicit app theme signals
    const onThemeEvent = (e: Event | CustomEvent<{ mode?: ThemeMode }>) => {
      const next = (e as CustomEvent<{ mode?: ThemeMode }>).detail?.mode
      if (next === 'dark' || next === 'light') setMode(next)
      else onChange()
    }
    const onStorage = (e: StorageEvent) => {
      if (!e.key) return
      const k = e.key.toLowerCase()
      if (k.includes('theme')) {
        const v = (e.newValue || '').toLowerCase()
        if (v === 'dark' || v === 'light') setMode(v as 'dark' | 'light')
        else onChange()
      }
    }
    window.addEventListener('themechange', onThemeEvent)
    window.addEventListener('storage', onStorage)
    // Mark body while ReDoc is mounted so we can style portal-based dropdowns
    const prev = document.body.getAttribute('data-redoc')
    document.body.setAttribute('data-redoc', '1')
    return () => {
      mo.disconnect()
      if (mql.removeEventListener) mql.removeEventListener('change', onChange)
      else mql.removeListener(onChange)
      window.removeEventListener('themechange', onThemeEvent)
      window.removeEventListener('storage', onStorage)
      // Restore previous value
      if (prev === null) document.body.removeAttribute('data-redoc')
      else document.body.setAttribute('data-redoc', prev)
    }
  }, [getMode])

  // Curated hex palettes for ReDoc (no CSS vars)
  const buildRedocTheme = useCallback((m: ThemeMode) => {
    const light = {
      colors: {
        primary: { main: '#4F46E5' }, // keep indigo accent per app
        text: { primary: '#09090B', secondary: '#3F3F46' }, // zinc-950 / zinc-700
        http: {
          get: '#10B981', post: '#3B82F6', put: '#F59E0B', delete: '#EF4444',
          options: '#06B6D4', patch: '#8B5CF6', basic: '#64748B', link: '#0EA5E9', head: '#A3A3A3',
        },
        border: { dark: '#E4E4E7' }, // zinc-200
        background: { default: '#FFFFFF', alternative: '#FAFAFA' }, // zinc-50
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
        backgroundColor: '#FAFAFA', // zinc-50
        textColor: '#09090B', // zinc-950
        width: '280px',
      },
      rightPanel: {
        backgroundColor: '#FFFFFF',
        textColor: '#09090B',
        width: '40%',
      },
      codeBlock: {
        backgroundColor: '#F4F4F5', // zinc-100
        textColor: '#18181B', // zinc-900
        tokens: {},
      },
    }
    const dark = {
      colors: {
        primary: { main: '#93C5FD' }, // blue-300 for clarity on dark
        text: { primary: '#E4E4E7', secondary: '#A1A1AA' }, // zinc-200 / zinc-400
        http: {
          get: '#34D399', post: '#60A5FA', put: '#FBBF24', delete: '#F87171',
          options: '#22D3EE', patch: '#A78BFA', basic: '#94A3B8', link: '#38BDF8', head: '#A3A3A3',
        },
        border: { dark: '#27272A' }, // zinc-800
        background: { default: '#09090B', alternative: '#18181B' }, // zinc-950 / zinc-900
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
        backgroundColor: '#18181B', // zinc-900
        textColor: '#E4E4E7',
        width: '280px',
      },
      rightPanel: {
        backgroundColor: '#09090B', // zinc-950
        textColor: '#E4E4E7',
        width: '40%',
      },
      codeBlock: {
        backgroundColor: '#18181B', // zinc-900
        textColor: '#E4E4E7',
        tokens: {},
      },
    }
    return m === 'dark' ? dark : light
  }, [])

  const redocTheme = useMemo(() => buildRedocTheme(mode), [mode, buildRedocTheme])
  // IMPORTANT: All hooks must run before any early returns to keep hook order stable
  const dynamicCss = useMemo(() => {
    const isDark = mode === 'dark'
    const heading = isDark ? '#E6E8EB' : '#0B1220'
    const headingAccent = isDark ? '#93C5FD' : '#4F46E5'
  const contentBg = isDark ? '#09090B' : '#FFFFFF' // zinc-950
  const contentText = isDark ? '#E4E4E7' : '#09090B'
  const mutedText = isDark ? '#A1A1AA' : '#3F3F46' // zinc-400 / zinc-700
    const link = isDark ? '#93C5FD' : '#4F46E5'
    const linkHover = isDark ? '#60A5FA' : '#4338CA'
    const rightBg = contentBg
    const rightText = contentText
  const rightBorder = isDark ? '#27272A' : '#E4E4E7' // zinc-800 / zinc-200
  const codeBg = isDark ? '#18181B' : '#F4F4F5' // zinc-900 / zinc-100
  const codeText = isDark ? '#E4E4E7' : '#18181B' // zinc-200 / zinc-900
  const rowAltBg = isDark ? '#18181B' : '#FAFAFA' // zinc-900 / zinc-50
  const tableHeaderBg = isDark ? '#18181B' : '#F4F4F5'
  const tableHeaderText = isDark ? '#E4E4E7' : '#18181B'
  const tabBorder = rightBorder
  const selectedTab = isDark ? '#93C5FD' : '#4F46E5'
  const inlineCodeBg = isDark ? '#27272A' : '#F4F4F5' // zinc-800 / zinc-100
  const inlineCodeText = isDark ? '#E4E4E7' : '#18181B'
  const controlBg = isDark ? '#18181B' : '#FFFFFF' // input/select control background
  const menuBg = isDark ? '#18181B' : '#FFFFFF'
  const menuHoverBg = isDark ? '#27272A' : '#F4F4F5'
  const menuSelectedBg = isDark ? '#27272A' : '#EEF2FF'
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
  .rd-theme input, .rd-theme select, .rd-theme textarea { background: ${controlBg} !important; color: ${contentText} !important; border: 1px solid ${rightBorder} !important; }
      .rd-theme input::placeholder, .rd-theme textarea::placeholder { color: ${mutedText} !important; opacity: 1 !important; }

  /* Dropdowns/Comboboxes (React-Select and ARIA role fallbacks) */
  .rd-theme .react-select__control,
  .rd-theme .Select__control,
  .rd-theme [class*='select__control'] { background: ${controlBg} !important; color: ${contentText} !important; border: 1px solid ${rightBorder} !important; }
  .rd-theme .react-select__placeholder,
  .rd-theme .react-select__single-value,
  .rd-theme [class*='select__placeholder'],
  .rd-theme [class*='select__single-value'] { color: ${mutedText} !important; }
  .rd-theme .react-select__menu,
  .rd-theme .Select__menu,
  .rd-theme [class*='select__menu'],
  .rd-theme [role='listbox'] { background: ${menuBg} !important; color: ${contentText} !important; border: 1px solid ${rightBorder} !important; }
  .rd-theme .react-select__option,
  .rd-theme .Select__option,
  .rd-theme [class*='select__option'],
  .rd-theme [role='option'] { background: ${menuBg} !important; color: ${contentText} !important; }
  .rd-theme .react-select__option--is-focused,
  .rd-theme .Select__option--is-focused,
  .rd-theme [class*='select__option--is-focused'],
  .rd-theme [role='option'][data-focus='true'] { background: ${menuHoverBg} !important; }
  .rd-theme .react-select__option--is-selected,
  .rd-theme .Select__option--is-selected,
  .rd-theme [class*='select__option--is-selected'],
  .rd-theme [role='option'][aria-selected='true'] { background: ${menuSelectedBg} !important; color: ${contentText} !important; }

  /* Global dropdown styles for portal-rendered menus (scoped via body[data-redoc]) */
  body[data-redoc] [role='listbox'],
  body[data-redoc] .react-select__menu,
  body[data-redoc] .react-select__menu-list,
  body[data-redoc] [class*='select__menu'],
  body[data-redoc] [class*='select__menu-list'] { background: ${menuBg} !important; color: ${contentText} !important; border: 1px solid ${rightBorder} !important; border-radius: 8px; z-index: 10000 !important; max-height: 60vh; overflow: auto; }
  body[data-redoc] [role='option'],
  body[data-redoc] .react-select__option,
  body[data-redoc] [class*='select__option'] { background: ${menuBg} !important; color: ${contentText} !important; }
  body[data-redoc] [role='option'] *,
  body[data-redoc] .react-select__option *,
  body[data-redoc] [class*='select__option'] * { color: ${contentText} !important; }
  body[data-redoc] [role='option'][data-focus='true'],
  body[data-redoc] .react-select__option--is-focused,
  body[data-redoc] [class*='select__option--is-focused'] { background: ${menuHoverBg} !important; }
  body[data-redoc] [role='option'][aria-selected='true'],
  body[data-redoc] .react-select__option--is-selected,
  body[data-redoc] [class*='select__option--is-selected'] { background: ${menuSelectedBg} !important; color: ${contentText} !important; }
  body[data-redoc] [role='option'][aria-selected='true'] *,
  body[data-redoc] .react-select__option--is-selected *,
  body[data-redoc] [class*='select__option--is-selected'] * { color: ${contentText} !important; }

  /* Removed broad generic menu/popover selectors to avoid affecting app sidebar */

  /* Styled-components containers used by ReDoc for server picker (class names may vary) */
  .rd-theme .sc-ecJghI,
  .rd-theme .sc-iyBeIh { background: ${menuBg} !important; color: ${contentText} !important; border: 1px solid ${rightBorder} !important; border-radius: 8px; }
  .rd-theme .sc-ecJghI *,
  .rd-theme .sc-iyBeIh * { color: ${contentText} !important; }
  .rd-theme .sc-ecJghI p,
  .rd-theme .sc-iyBeIh p { color: ${mutedText} !important; }
  body[data-redoc] .sc-ecJghI,
  body[data-redoc] .sc-iyBeIh { background: ${menuBg} !important; color: ${contentText} !important; border: 1px solid ${rightBorder} !important; border-radius: 8px; }
  body[data-redoc] .sc-ecJghI *,
  body[data-redoc] .sc-iyBeIh * { color: ${contentText} !important; }
  body[data-redoc] .sc-ecJghI p,
  body[data-redoc] .sc-iyBeIh p { color: ${mutedText} !important; }
  body[data-redoc] [role='combobox'],
  body[data-redoc] [aria-haspopup='listbox'] { background: ${controlBg} !important; color: ${contentText} !important; border: 1px solid ${rightBorder} !important; }

  /* Server URL control rendered as a generic button */
  .rd-theme [role='button'] > div { background: ${controlBg} !important; color: ${contentText} !important; border: 1px solid ${rightBorder} !important; border-radius: 8px; padding: 8px 10px; }
  .rd-theme [role='button'] > div * { color: ${contentText} !important; }
  /* Removed body-scoped generic role=button styling to prevent bleeding */

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

  const params = useParams<{ api?: string }>()
  const readSpecFromUrl = (): Spec => {
    // Prefer route param when provided (e.g., /docs/api/:api/spec)
    const routeApi = params.api as string | undefined
    const fromRoute = (routeApi || '').toLowerCase()
    if (fromRoute === 'auth') return 'auth'
    if (fromRoute === 'admin') return 'admin'
    if (fromRoute === 'pets') return 'pets'
    // Fallback to query param
    if (typeof window !== 'undefined') {
      const u = new URL(window.location.href)
      const which = (u.searchParams.get('spec') || '').toLowerCase()
      if (which === 'auth') return 'auth'
      if (which === 'admin') return 'admin'
      if (which === 'pets') return 'pets'
    }
    // Last fallback: localStorage remembered choice
    try {
      const last = (localStorage.getItem('docs:lastSpec') || '').toLowerCase()
      if (last === 'auth' || last === 'admin' || last === 'pets') return last as Spec
  } catch { /* ignore docs storage */ }
    return 'pets'
  }
  const [spec, setSpec] = useState<Spec>(readSpecFromUrl())

  useEffect(() => {
    // If we're on legacy /docs with ?spec=, redirect to new path
    const u = new URL(window.location.href)
    if (u.pathname === '/docs') {
      const s = (u.searchParams.get('spec') || readSpecFromUrl()).toLowerCase() as Spec
      const next = s === 'admin' || s === 'auth' || s === 'pets' ? s : 'pets'
      const to = `/docs/api/${next}/spec`
      window.history.replaceState({}, '', to)
    }
    const onPop = () => setSpec(readSpecFromUrl())
    window.addEventListener('popstate', onPop)
    return () => window.removeEventListener('popstate', onPop)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params.api])

  // Version switching
  type VersionMode = 'latest' | 'versioned'
  const [versionMode, setVersionMode] = useState<VersionMode>(() => {
  try { return (localStorage.getItem('docs:versionMode') as VersionMode) || 'latest' } catch { return 'latest' }
  })
  const [currentVersion, setCurrentVersion] = useState<string>('')

  // Resolve the JSON URL based on spec + version mode. When versioned, we need the semantic version.
  const baseJsonUrl = (s: Spec) => {
    if (s === 'admin') return '/api-docs/admin'
    if (s === 'auth') return '/auth-docs'
    return '/api-docs'
  }
  const latestJsonUrl = `${baseJsonUrl(spec)}/latest/openapi.json`

  useEffect(() => {
    // Persist choices
  try { localStorage.setItem('docs:lastSpec', spec) } catch { /* ignore */ }
  }, [spec])
  useEffect(() => {
  try { localStorage.setItem('docs:versionMode', versionMode) } catch { /* ignore */ }
  }, [versionMode])

  useEffect(() => {
    // Fetch version from latest to derive versioned URL label
    let aborted = false
    const fetchVersion = async () => {
      try {
        const res = await fetch(latestJsonUrl, { credentials: 'include' })
        if (!res.ok) return
        const json = await res.json()
        const v = String(json?.info?.version || '').trim()
        if (!aborted) setCurrentVersion(v)
  } catch { /* ignore fetch errors */ }
    }
    fetchVersion()
    return () => { aborted = true }
  }, [latestJsonUrl])

  const specUrl = versionMode === 'latest'
    ? latestJsonUrl
    : `${baseJsonUrl(spec)}/v${(currentVersion || '0.0.0')}/openapi.json`

  const onChangeSpec = (next: Spec) => {
    setSpec(next)
    if (typeof window !== 'undefined') {
      // Prefer clean path: /docs/api/:api/spec
      const to = `/docs/api/${next}/spec`
      window.history.pushState({}, '', to)
    }
  }

  // Let ReDoc fetch the spec via specUrl so its search index initializes properly

  return (
    <div className="rd-theme w-full min-h-[80vh] rounded-xl">
      <div className="flex items-center justify-end gap-3 px-3 py-2">
        <div className="flex items-center gap-2">
          <label className="text-xs opacity-70" htmlFor="spec-picker">API</label>
          <select
            id="spec-picker"
            className="border rounded-md text-sm px-2 py-1 bg-transparent"
            value={spec}
            onChange={(e) => onChangeSpec(e.target.value as Spec)}
          >
            <option value="pets">Pets REST API</option>
            <option value="auth">Auth REST API</option>
            <option value="admin">Admin REST API</option>
          </select>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs opacity-70" htmlFor="version-picker">Version</label>
          <select
            id="version-picker"
            className="border rounded-md text-sm px-2 py-1 bg-transparent"
            value={versionMode}
            onChange={(e) => setVersionMode(e.target.value as VersionMode)}
          >
            <option value="latest">Latest</option>
            <option value="versioned">{currentVersion ? `Current (${currentVersion})` : 'Current (loading...)'}</option>
          </select>
        </div>
      </div>
      <Suspense fallback={<div className="p-4 text-sm opacity-70">Loading viewer…</div>}>
        <RedocStandaloneLazy
          key={`redoc-${mode}-${spec}`}
          specUrl={specUrl}
          options={{
            // Redoc typings expect its own theme interface; our object matches but TS can't infer it here.
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
