import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import RootLayout from './layout/root-layout'
import DashboardPage from './dashboard/page'
import RedocPage from './docs/redoc-page'

// Enable dark theme by default so the shadcn block displays in its dark mode
if (typeof document !== 'undefined') {
  document.documentElement.classList.add('dark')
}

const router = createBrowserRouter([
  {
    path: '/',
    element: <RootLayout />,
    children: [
      { index: true, element: <DashboardPage /> },
      { path: 'docs', element: <RedocPage /> },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router} />
  </StrictMode>,
)
