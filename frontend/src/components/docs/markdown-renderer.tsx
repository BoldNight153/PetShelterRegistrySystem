import React from 'react'
import ReactMarkdown from 'react-markdown'
import remarkDirective from 'remark-directive'
import remarkGfm from 'remark-gfm'
import type { Element as HastEl, Properties as HastProps } from 'hast'
import { rehypeInlineCodeProperty, isInlineCode } from 'react-shiki'
import type { Theme as ShikiTheme, Themes as ShikiThemes, HighlighterOptions as ShikiHighlighterOptions, Element as HastElement } from 'react-shiki'
import 'react-shiki/css'
import { CodeBlock as RichCodeBlock } from '@/components/docs/code-block'
import { CodeTabs } from '@/components/docs/code-tabs'
import { useDocsLightbox } from '@/components/docs/lightbox-context'
import { remarkTabs } from '@/components/docs/remark-tabs'

//

export type CodeThemeName = ShikiTheme | ShikiThemes
export type CodeThemeDefaultColor = ShikiHighlighterOptions['defaultColor']

type RMCodeProps = React.ComponentPropsWithoutRef<'code'> & { node?: HastElement }

function CodeBlock(props: RMCodeProps & { theme: CodeThemeName; defaultColor?: CodeThemeDefaultColor }) {
  const { className, children, node, ...rest } = props
  const code = String(children ?? '').trim()
  const match = /language-([\w-]+)/.exec(className || '')
  const language = match?.[1]
  const inline = node ? isInlineCode(node) : false
  if (inline || !language) return <code className={className} {...rest}>{children}</code>
  return <RichCodeBlock code={code} language={language} />
}

function DiagramImage(props: React.ImgHTMLAttributes<HTMLImageElement>) {
  const { open } = useDocsLightbox()
  const isDiagram = typeof props.src === 'string' && props.src.startsWith('/images/docs/')
  const img = <img {...props} className={['diagram', props.className].filter(Boolean).join(' ')} />
  if (!isDiagram) return img
  const title = props.title || props.alt || 'Diagram'
  const description = props.alt && props.title ? props.alt : undefined
  return (
    <figure className="diagram-figure">
      {img}
      <button
        type="button"
        className="diagram-open-btn"
        aria-label="Open full size"
        onClick={() => open([{ src: props.src!, alt: props.alt, title, description }])}
      >
        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 3h6v6"/><path d="M9 21H3v-6"/><path d="M21 3l-7 7"/><path d="M3 21l7-7"/></svg>
      </button>
    </figure>
  )
}

import type { Components } from 'react-markdown'

export function MarkdownRenderer({ markdown, theme, defaultColor }: { markdown: string; theme: CodeThemeName; defaultColor?: CodeThemeDefaultColor }) {
  // tabs handled by remarkTabs
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm, remarkDirective, remarkTabs]}
      rehypePlugins={[rehypeInlineCodeProperty]}
      components={{
        code: (props: RMCodeProps) => <CodeBlock {...props} theme={theme} defaultColor={defaultColor} />,
        img: (props: React.ImgHTMLAttributes<HTMLImageElement>) => <DiagramImage {...props} />,
        div: ({ node, ...p }: { node?: unknown }) => {
          // Render our tabs container
          // Expect children structure to be paragraphs/headings and code blocks with titles
          const hast = node as unknown as HastEl
          const props = (hast?.properties ?? {}) as HastProps
          const isTabs = props['data-tabs']
          if (!isTabs) return <div {...p} />

          // Extract immediate children that are headings or code blocks; use title attribute when present
          const items: Array<{ id: string; title: string; content: React.ReactNode }> = []
          const children = (hast.children ?? []) as Array<unknown>
          let idx = 0
          for (const childNode of children) {
            const child = childNode as Partial<HastEl> & { type?: string; children?: Array<unknown> }
            if (child && (child as unknown as { type?: string }).type === 'element' && child.tagName === 'pre') {
              const first = child.children?.[0] as Partial<HastEl> & { tagName?: string }
              if (first?.tagName !== 'code') continue
              const codeEl = first as HastEl
              const cls = (codeEl.properties?.className as string[] | undefined)?.[0]
              const title = codeEl.properties?.title as string | undefined
              const langMatch = cls ? /language-([\w-]+)/.exec(cls) : null
              const lang = langMatch?.[1] ?? 'text'
              const firstChild = codeEl.children?.[0] as unknown as { value?: string }
              const raw = firstChild?.value as string | undefined
              if (raw) {
                items.push({ id: `t${idx++}`, title: title || lang, content: <RichCodeBlock code={raw} language={lang} /> })
              }
            }
          }
          if (!items.length) return <div {...p} />
          return <CodeTabs items={items} />
        },
      } as Partial<Components>}
    >
      {markdown}
    </ReactMarkdown>
  )
}
