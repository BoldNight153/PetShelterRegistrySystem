import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import AdminSettingsPage from './settings'
import { renderWithProviders } from '@/test-utils/renderWithProviders'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

vi.mock('@/lib/auth-context', () => {
  return {
    useAuth: () => ({ user: { email: 'admin@example.com', roles: ['system_admin'] } }),
  }
})

const saveSettingsMock = vi.fn().mockResolvedValue({ ok: true })
const loadSettingsMock = vi.fn().mockResolvedValue({
  security: {
    sessionMaxAgeMin: 60,
    requireEmailVerification: true,
    loginIpWindowSec: 60,
    loginIpLimit: 20,
    loginLockWindowSec: 900,
    loginLockThreshold: 5,
    loginLockDurationMin: 15,
    passwordHistoryLimit: 10,
  },
})

const navigationMenuMock = {
  id: 'settings_main',
  name: 'Settings',
  items: [
    {
      id: 'security-group',
      title: 'Security',
      isPublished: true,
      isVisible: true,
      children: [
        {
          id: 'security-core',
          title: 'Security',
          url: '/settings/security',
          isPublished: true,
          isVisible: true,
          meta: { settingsCategory: 'security' },
        },
      ],
    },
  ],
}

const navigationServiceStub = {
  listMenus: vi.fn().mockResolvedValue([navigationMenuMock]),
  getMenu: vi.fn().mockResolvedValue(navigationMenuMock),
  createMenu: vi.fn().mockResolvedValue(null),
  updateMenu: vi.fn().mockResolvedValue(null),
  deleteMenu: vi.fn().mockResolvedValue(undefined),
  createMenuItem: vi.fn().mockResolvedValue(null),
  updateMenuItem: vi.fn().mockResolvedValue(null),
  deleteMenuItem: vi.fn().mockResolvedValue(undefined),
}

describe('AdminSettingsPage (Security)', () => {
  beforeEach(() => {
    saveSettingsMock.mockClear()
    loadSettingsMock.mockClear()
    navigationServiceStub.listMenus.mockClear()
    navigationServiceStub.listMenus.mockResolvedValue([navigationMenuMock])
    navigationServiceStub.getMenu.mockClear()
    navigationServiceStub.getMenu.mockResolvedValue(navigationMenuMock)
  })

  it('saves security settings including new thresholds', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: {
          settings: { loadSettings: loadSettingsMock, saveSettings: saveSettingsMock },
          navigation: navigationServiceStub,
        },
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })
    render(<AdminSettingsPage />, { wrapper })

    // Wait for settings to load
    await waitFor(() => expect(loadSettingsMock).toHaveBeenCalledTimes(1))

    // Click Save Security
    const saveBtn = await screen.findByRole('button', { name: /save security/i })
    fireEvent.click(saveBtn)

    await waitFor(() => expect(saveSettingsMock).toHaveBeenCalled())

    const [category, entries] = saveSettingsMock.mock.calls.at(-1)!
    expect(category).toBe('security')
    const keys = (entries as Array<{ key: string; value: unknown }>).map(e => e.key)
    // Ensure all expected keys are present
    expect(keys).toEqual(expect.arrayContaining([
      'sessionMaxAgeMin',
      'requireEmailVerification',
      'loginIpWindowSec',
      'loginIpLimit',
      'loginLockWindowSec',
      'loginLockThreshold',
      'loginLockDurationMin',
      'passwordHistoryLimit',
    ]))
  })

  it('toggles a security flag and saves the changed value', async () => {
    // Start with requireEmailVerification = true from loadSettingsMock
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: {
          settings: { loadSettings: loadSettingsMock, saveSettings: saveSettingsMock },
          navigation: navigationServiceStub,
        },
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })
    render(<AdminSettingsPage />, { wrapper })

    // Wait for settings to load
    await waitFor(() => expect(loadSettingsMock).toHaveBeenCalledTimes(1))

    // Toggle the Require email verification checkbox (control text is the inline label)
    const checkbox = await screen.findByRole('checkbox', { name: /Enforce verification/i })
    // initial should be checked
    expect((checkbox as HTMLInputElement).checked).toBe(true)
    fireEvent.click(checkbox)
    expect((checkbox as HTMLInputElement).checked).toBe(false)

    // Click Save Security
    const saveBtn = await screen.findByRole('button', { name: /save security/i })
    fireEvent.click(saveBtn)

    await waitFor(() => expect(saveSettingsMock).toHaveBeenCalled())

    const [category, entries] = saveSettingsMock.mock.calls.at(-1)!
    expect(category).toBe('security')
    const changed = (entries as Array<{ key: string; value: unknown }>).find(e => e.key === 'requireEmailVerification')
    expect(changed).toBeDefined()
    expect(changed!.value).toBe(false)
  })
})

describe('AdminSettingsPage (Access control)', () => {
  it('shows access denied for non-admins', async () => {
    // Reset module registry to apply a different mock
    vi.resetModules()
    vi.doMock('@/lib/auth-context', () => ({ useAuth: () => ({ user: { email: 'user@example.com', roles: [] } }) }))
    const { default: NonAdminSettings } = await import('./settings')
    // Import a fresh ServicesProvider from the reset module registry so the component uses the same context instance
    const { ServicesProvider: FreshServicesProvider } = await import('@/services/provider')
    // Wrap the fresh provider with a QueryClientProvider to ensure queries can run
    const qc = new QueryClient()
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <FreshServicesProvider
            services={{
              admin: {
                settings: { loadSettings: loadSettingsMock, saveSettings: saveSettingsMock },
                navigation: navigationServiceStub,
              },
              navigation: navigationServiceStub,
            }}
          >
            <NonAdminSettings />
          </FreshServicesProvider>
        </MemoryRouter>
      </QueryClientProvider>
    )
    expect(await screen.findByText(/access denied/i)).toBeInTheDocument()
  })
})
