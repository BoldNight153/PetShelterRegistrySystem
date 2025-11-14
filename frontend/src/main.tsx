import React, { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import RootLayout from './layout/root-layout'
import DashboardPage from './dashboard/page'
import RedocPage from './docs/redoc-page'
import LoginPage from './pages/login'
import RegisterPage from './pages/register'
import { AuthProvider } from './lib/auth-context'
import { ServicesProvider, default as ServicesContext } from './services/provider'
import { Provider } from 'react-redux'
import { createStoreWithServices } from './store/store'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ReactQueryDevtools } from '@tanstack/react-query-devtools'
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
import AdminUsersPage from './pages/admin/users'
import AdminRolesPage from './pages/admin/roles'
import AdminPermissionsPage from './pages/admin/permissions'
import AdminAboutPage from './pages/admin/about'
import AboutPage from './pages/about'
import NotFoundPage from './pages/not-found'
import StatusPageRoute from './pages/errors/status-route'
import UnderConstructionPage from './pages/under-construction'
import NavigationBuilderPage from './pages/admin/navigation-builder'
import ProfileSettingsPage from './pages/settings/account/profile'

// Do not force a default theme here; theme is initialized in index.html before React mounts.

const adminPlaceholderRoutes = [
  { path: 'alerts', feature: 'Alerts center' },
  { path: 'events/upcoming', feature: 'Upcoming events' },
  { path: 'animals', feature: 'Animal directory' },
  { path: 'animals/intake', feature: 'Animal intake workflow' },
  { path: 'animals/adoptions', feature: 'Adoptions dashboard' },
  { path: 'animals/medical', feature: 'Medical records' },
  { path: 'animals/events', feature: 'Animal event history' },
  { path: 'people/owners', feature: 'Pet owners' },
  { path: 'people/fosters', feature: 'Foster network' },
  { path: 'people/volunteers', feature: 'Volunteer roster' },
  { path: 'people/contacts', feature: 'Contact directory' },
  { path: 'facilities/locations', feature: 'Facility locations' },
  { path: 'facilities/capacity', feature: 'Capacity planning' },
  { path: 'facilities/maintenance', feature: 'Maintenance schedule' },
  { path: 'facilities/inventory', feature: 'Inventory management' },
  { path: 'schedule/calendar', feature: 'Scheduling calendar' },
  { path: 'schedule/shifts', feature: 'Shift scheduling' },
  { path: 'schedule/follow-ups', feature: 'Follow-up queue' },
  { path: 'schedule/reminders', feature: 'Reminders inbox' },
  { path: 'reports/outcomes', feature: 'Outcome reports' },
  { path: 'reports/intake-vs-adoption', feature: 'Intake vs adoption report' },
  { path: 'reports/compliance', feature: 'Compliance report' },
  { path: 'reports/exports', feature: 'Data exports' },
  { path: 'projects/active', feature: 'Active projects' },
  { path: 'projects/new', feature: 'New project wizard' },
  { path: 'projects/archived', feature: 'Archived projects' },
  { path: 'settings/integrations', feature: 'Integrations hub' },
]

const router = createBrowserRouter([
  {
    path: '/',
    element: <RootLayout />,
    children: [
  { index: true, element: <AboutPage /> },
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
      { path: 'server-info', element: (
        <ProtectedRoute>
          <ServerDashboard />
        </ProtectedRoute>
      ) },
      { path: 'server-info/charts', element: (
        <ProtectedRoute>
          <ServerInfoCharts />
        </ProtectedRoute>
      ) },
      { path: 'settings', element: (
        <ProtectedRoute>
          <AdminSettingsPage />
        </ProtectedRoute>
      ) },
      { path: 'settings/general', element: (
        <ProtectedRoute>
          <AdminSettingsPage />
        </ProtectedRoute>
      ) },
      { path: 'audit-logs', element: (
        <ProtectedRoute>
          <AuditLogsPage />
        </ProtectedRoute>
      ) },
      { path: 'settings/users', element: (
        <ProtectedRoute>
          <AdminUsersPage />
        </ProtectedRoute>
      ) },
      { path: 'settings/roles', element: (
        <ProtectedRoute>
          <AdminRolesPage />
        </ProtectedRoute>
      ) },
      { path: 'settings/permissions', element: (
        <ProtectedRoute>
          <AdminPermissionsPage />
        </ProtectedRoute>
      ) },
      { path: 'settings/navigation', element: (
        <ProtectedRoute>
          <NavigationBuilderPage />
        </ProtectedRoute>
      ) },
      { path: 'settings/account/profile', element: (
        <ProtectedRoute>
          <ProfileSettingsPage />
        </ProtectedRoute>
      ) },
      { path: 'settings/logs', element: (
        <ProtectedRoute>
          <AuditLogsPage />
        </ProtectedRoute>
      ) },
      { path: 'system/about', element: (
        <ProtectedRoute>
          <AdminAboutPage />
        </ProtectedRoute>
      ) },
      // Legacy alias for Audit Logs
      { path: 'audit', element: (
        <ProtectedRoute>
          <AuditLogsPage />
        </ProtectedRoute>
      ) },
      // Keep legacy admin/docs/* content pages accessible without auth
  { path: 'docs/introduction', element: <DocsIntroduction /> },
  { path: 'docs/get-started', element: <DocsGetStarted /> },
  { path: 'docs/tutorials', element: <DocsTutorials /> },
      { path: 'docs/examples', element: <AdminDocsExamples /> },
  { path: 'docs/changelog', element: <DocsChangelog /> },
      ...adminPlaceholderRoutes.map(({ path, feature }) => ({
        path,
        element: (
          <ProtectedRoute>
            <UnderConstructionPage feature={feature} />
          </ProtectedRoute>
        ),
      })),
      { path: 'login', element: <LoginPage /> },
      { path: 'register', element: <RegisterPage /> },
  { path: 'signup', element: <RegisterPage /> },
      { path: 'errors/:code', element: <StatusPageRoute /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
])

function AppProviders({ children }: { children: React.ReactNode }) {
  // ServicesProvider must sit above so tests or runtime can override adapters.
  return (
    <ServicesProvider>
      <ProvidersInner>{children}</ProvidersInner>
    </ServicesProvider>
  )
}

function ProvidersInner({ children }: { children: React.ReactNode }) {
  const services = React.useContext(ServicesContext)
  const store = React.useMemo(() => createStoreWithServices(services), [services])
  return (
    <Provider store={store}>
      <QueryClientProvider client={new QueryClient()}>
        <AuthProvider>
          {children}
        </AuthProvider>
        <ReactQueryDevtools initialIsOpen={false} />
      </QueryClientProvider>
    </Provider>
  )
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AppProviders>
      <RouterProvider router={router} />
    </AppProviders>
  </StrictMode>,
)
