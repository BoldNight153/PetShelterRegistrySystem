import { createContext, useContext } from 'react'
import type { Slide } from 'yet-another-react-lightbox'

type LightboxCtx = {
  open: (slides: Slide[], index?: number) => void
}

export const DocsLightboxCtx = createContext<LightboxCtx | null>(null)

export function useDocsLightbox() {
  const ctx = useContext(DocsLightboxCtx)
  if (!ctx) throw new Error('useDocsLightbox must be used within <DocsLightboxProvider>')
  return ctx
}
