import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import Page from './dashboard/page.tsx'

// Enable dark theme by default so the shadcn block displays in its dark mode
if (typeof document !== 'undefined') {
  document.documentElement.classList.add('dark')
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Page />
  </StrictMode>,
)
