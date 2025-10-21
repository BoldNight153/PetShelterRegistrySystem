import { useCallback, useMemo, useState } from 'react'
import Lightbox, { type Slide } from 'yet-another-react-lightbox'
import Captions from 'yet-another-react-lightbox/plugins/captions'
import Zoom from 'yet-another-react-lightbox/plugins/zoom'
import 'yet-another-react-lightbox/styles.css'
import 'yet-another-react-lightbox/plugins/captions.css'
import { DocsLightboxCtx } from '@/components/docs/lightbox-context'

export function DocsLightboxProvider({ children }: { children: React.ReactNode }) {
  // Slides state for the lightbox; allow captions/extra fields via Slide type
  const [slidesState, setSlidesState] = useState<Slide[] | null>(null)
  const [index, setIndex] = useState(0)

  const open = useCallback((s: Slide[], i = 0) => {
    setSlidesState(s)
    setIndex(i)
  }, [])

  const ctx = useMemo(() => ({ open }), [open])

  return (
    <DocsLightboxCtx.Provider value={ctx}>
      {children}
      {slidesState && (
        <Lightbox
          open={slidesState != null}
          close={() => setSlidesState(null)}
          slides={slidesState}
          index={index}
          plugins={[Captions, Zoom]}
          animation={{ zoom: 400 }}
          captions={{
            showToggle: true,
            descriptionTextAlign: 'start',
            descriptionMaxLines: 6,
          }}
          zoom={{
            scrollToZoom: true,
            minZoom: 1,
            maxZoomPixelRatio: 3.5,
            zoomInMultiplier: 1.6,
            doubleClickDelay: 300,
            doubleClickMaxStops: 2,
            keyboardMoveDistance: 50,
            wheelZoomDistanceFactor: 120,
            pinchZoomDistanceFactor: 1,
          }}
          render={{
            buttonPrev: () => null,
            buttonNext: () => null,
          }}
        />
      )}
    </DocsLightboxCtx.Provider>
  )
}
