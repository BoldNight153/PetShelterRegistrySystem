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
import DocsIntroduction from './pages/docs/introduction'
import DocsGetStarted from './pages/docs/get-started'
import DocsTutorials from './pages/docs/tutorials'
import DocsChangelog from './pages/docs/changelog'
import DocsArchitecture from './pages/docs/architecture'
import DocsClientSDKs from './pages/docs/client-sdks'
import AdminDocsExamples from './pages/admin/docs/examples'
import AdminSettingsPage from './pages/admin/settings'
import AuditLogsPage from './pages/admin/audit-logs'

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
  // Legacy docs entrypoint with query param support
  { path: 'docs', element: <RedocPage /> },
  // New docs IA: /docs/api/:api/spec and content pages per API
  { path: 'docs/api/:api/spec', element: <RedocPage /> },
  { path: 'docs/api/:api/introduction', element: <DocsIntroduction /> },
  { path: 'docs/api/:api/get-started', element: <DocsGetStarted /> },
  { path: 'docs/api/:api/tutorials', element: <DocsTutorials /> },
  { path: 'docs/api/:api/changelog', element: <DocsChangelog /> },
  // Other docs categories
  { path: 'docs/architecture', element: <DocsArchitecture /> },
  { path: 'docs/client-sdks', element: <DocsClientSDKs /> },
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
      { path: 'admin/audit-logs', element: (
        <ProtectedRoute>
          <AuditLogsPage />
        </ProtectedRoute>
      ) },
      // Legacy alias for Audit Logs
      { path: 'admin/audit', element: (
        <ProtectedRoute>
          <AuditLogsPage />
        </ProtectedRoute>
      ) },
      // Keep legacy admin/docs/* content pages accessible without auth
  { path: 'admin/docs/introduction', element: <DocsIntroduction /> },
  { path: 'admin/docs/get-started', element: <DocsGetStarted /> },
  { path: 'admin/docs/tutorials', element: <DocsTutorials /> },
      { path: 'admin/docs/examples', element: <AdminDocsExamples /> },
  { path: 'admin/docs/changelog', element: <DocsChangelog /> },
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
