import * as React from 'react'
import { ShikiHighlighter } from 'react-shiki/web'

type CodeTheme = 'system' | 'light' | 'dark' | 'dim'

function themeMap(sel: CodeTheme) {
  switch (sel) {
    case 'light':
      return 'github-light-high-contrast'
    case 'dark':
      return 'github-dark-high-contrast'
    case 'dim':
      return 'github-dark-dimmed'
    case 'system':
    default:
      return { light: 'github-light-high-contrast', dark: 'github-dark-high-contrast' }
  }
}

function defaultColorFor(sel: CodeTheme): 'light' | 'dark' | 'light-dark()' | undefined {
  return sel === 'system' ? 'light-dark()' : undefined
}

export function CodeBlock({ code, language }: { code: string; language: string }) {
  const [override, setOverride] = React.useState<CodeTheme>('system')
  const [copied, setCopied] = React.useState(false)

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      // ignore
    }
  }

  const selTheme = themeMap(override)
  const defaultColor = defaultColorFor(override)

  return (
    <div className="group relative">
      <div className="absolute right-2 top-2 z-10 flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
        <select
          aria-label="Code theme"
          className="rounded border bg-background/80 px-1 py-0.5 text-xs"
          value={override}
          onChange={(e) => setOverride(e.target.value as CodeTheme)}
        >
          <option value="system">System</option>
          <option value="light">Light</option>
          <option value="dark">Dark</option>
          <option value="dim">Dim</option>
        </select>
        <button
          type="button"
          onClick={onCopy}
          className="rounded border bg-background/80 px-2 py-0.5 text-xs"
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      {copied && (
        <div
          role="status"
          aria-live="polite"
          className="pointer-events-none absolute right-2 top-10 z-10 rounded bg-foreground px-2 py-1 text-xs text-background shadow transition-opacity"
        >
          Copied!
        </div>
      )}
      <ShikiHighlighter language={language} theme={selTheme} defaultColor={defaultColor}>
        {code}
      </ShikiHighlighter>
    </div>
  )
}
