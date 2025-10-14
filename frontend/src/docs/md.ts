// Markdown utilities for loading docs content at build time via Vite
// This module exposes a loader that returns raw markdown strings.

export const mdFiles = import.meta.glob('/src/docs/content/**/*.md', {
  query: '?raw',
  import: 'default',
  eager: false,
}) as Record<string, () => Promise<string>>

export async function loadMarkdown(path: string): Promise<string> {
  const loader = mdFiles[path]
  if (!loader) throw new Error(`Markdown not found: ${path}`)
  return loader()
}

export async function renderMarkdownToHtml(path: string): Promise<string> {
  // Backwards compat shim: now we return the raw markdown
  return loadMarkdown(path)
}
