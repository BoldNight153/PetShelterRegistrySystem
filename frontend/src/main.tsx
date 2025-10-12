import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import RootLayout from './layout/root-layout'
import DashboardPage from './dashboard/page'
import RedocPage from './docs/redoc-page'
import LoginPage from './pages/login'
import RegisterPage from './pages/register'
import { AuthProvider } from './lib/auth-context'
import { ProtectedRoute } from './lib/auth-context'
import ServerInfoCharts from './pages/admin/server-info-charts'
import ServerDashboard from './pages/admin/server-dashboard'
import AdminDocsIntroduction from './pages/admin/docs/introduction'
import AdminDocsGetStarted from './pages/admin/docs/get-started'
import AdminDocsTutorials from './pages/admin/docs/tutorials'
import AdminDocsChangelog from './pages/admin/docs/changelog'
import AdminDocsExamples from './pages/admin/docs/examples'
import AdminSettingsPage from './pages/admin/settings'

// Do not force a default theme here; theme is initialized in index.html before React mounts.

const router = createBrowserRouter([
  {
    path: '/',
    element: <RootLayout />,
    errorElement: (
      <div className="p-6">
        <h1 className="text-2xl font-semibold mb-2">Page not found</h1>
        <p className="mb-4">The page you’re looking for doesn’t exist. Go back to the dashboard.</p>
        <a href="/" className="underline">Return home</a>
      </div>
    ),
    children: [
      { index: true, element: <RedocPage /> },
      { path: 'docs', element: <RedocPage /> },
      { path: 'dashboard', element: (
        <ProtectedRoute>
          <DashboardPage />
        </ProtectedRoute>
      ) },
      { path: 'admin/server-info', element: (
        <ProtectedRoute>
          <ServerDashboard />
        </ProtectedRoute>
      ) },
      { path: 'admin/server-info/charts', element: (
        <ProtectedRoute>
          <ServerInfoCharts />
        </ProtectedRoute>
      ) },
      { path: 'admin/settings', element: (
        <ProtectedRoute>
          <AdminSettingsPage />
        </ProtectedRoute>
      ) },
      { path: 'admin/docs/introduction', element: (
        <ProtectedRoute>
          <AdminDocsIntroduction />
        </ProtectedRoute>
      ) },
      { path: 'admin/docs/get-started', element: (
        <ProtectedRoute>
          <AdminDocsGetStarted />
        </ProtectedRoute>
      ) },
      { path: 'admin/docs/tutorials', element: (
        <ProtectedRoute>
          <AdminDocsTutorials />
        </ProtectedRoute>
      ) },
      { path: 'admin/docs/examples', element: (
        <ProtectedRoute>
          <AdminDocsExamples />
        </ProtectedRoute>
      ) },
      { path: 'admin/docs/changelog', element: (
        <ProtectedRoute>
          <AdminDocsChangelog />
        </ProtectedRoute>
      ) },
      { path: 'login', element: <LoginPage /> },
      { path: 'register', element: <RegisterPage /> },
  { path: 'signup', element: <RegisterPage /> },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
  <RouterProvider router={router} />
    </AuthProvider>
  </StrictMode>,
)
