import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import AdminSettingsPage from './settings'
import { renderWithProviders } from '@/test-utils/renderWithProviders'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import NotificationsSettingsPage from '@/pages/settings/account/notifications'
import type {
  IAdminNavigationService,
  IAdminAuthenticatorCatalogService,
  AdminAuthenticatorCatalogRecord,
  IAdminService,
} from '@/services/interfaces/admin.interface'
import type { INavigationService } from '@/services/interfaces/navigation.interface'
import { DEFAULT_NOTIFICATION_SETTINGS } from '@/types/notifications'

vi.mock('@/lib/auth-context', () => {
  return {
    useAuth: () => ({ user: { email: 'admin@example.com', roles: ['system_admin'] } }),
  }
})

const saveSettingsMock = vi.fn().mockResolvedValue({ ok: true })
const DEFAULT_SECURITY_SETTINGS = {
  sessionMaxAgeMin: 60,
  requireEmailVerification: true,
  loginIpWindowSec: 60,
  loginIpLimit: 20,
  loginLockWindowSec: 900,
  loginLockThreshold: 5,
  loginLockDurationMin: 15,
  passwordHistoryLimit: 10,
}

const loadSettingsMock = vi.fn().mockResolvedValue({
  security: { ...DEFAULT_SECURITY_SETTINGS },
  auth: {
    mode: 'session',
    google: true,
    github: false,
    enforceMfa: 'recommended',
    authenticators: ['google', 'microsoft', 'backup_codes'],
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
        {
          id: 'auth-core',
          title: 'Authentication',
          url: '/settings/security/authentication',
          isPublished: true,
          isVisible: true,
          meta: { settingsCategory: 'auth' },
        },
        {
          id: 'profile-link',
          title: 'Profile',
          url: '/settings/account/profile',
          isPublished: true,
          isVisible: true,
          meta: { settingsRoute: '/settings/account/profile' },
        },
        {
          id: 'legacy-profile-link',
          title: 'Account Overview',
          url: '/settings/account/overview',
          isPublished: true,
          isVisible: true,
        },
        {
          id: 'organization-settings',
          title: 'Organization Settings',
          url: '/settings/organization',
          isPublished: true,
          isVisible: true,
          meta: { settingsCategory: 'general' },
        },
      ],
    },
  ],
}

const listNavigationMenusMock = vi.fn().mockResolvedValue([navigationMenuMock])
const getNavigationMenuMock = vi.fn().mockResolvedValue(navigationMenuMock)

const navigationServiceStub: INavigationService = {
  listMenus: listNavigationMenusMock,
  getMenu: getNavigationMenuMock,
}

const adminListMenusMock = vi.fn().mockResolvedValue([])
const adminGetMenuMock = vi.fn().mockResolvedValue(null)
const adminCreateMenuMock = vi.fn().mockResolvedValue({ id: 'menu-id', name: 'Menu' })
const adminUpdateMenuMock = vi.fn().mockResolvedValue({ id: 'menu-id', name: 'Menu' })
const adminDeleteMenuMock = vi.fn().mockResolvedValue(undefined)
const adminListMenuItemsMock = vi.fn().mockResolvedValue([])
const adminCreateMenuItemMock = vi.fn().mockResolvedValue({
    id: 'item-id',
    menuId: 'menu-id',
    parentId: null,
    title: 'Item',
    url: null,
    icon: null,
    target: null,
    external: null,
    order: 0,
    meta: null,
    isVisible: true,
    isPublished: true,
    locale: null,
    createdAt: null,
    updatedAt: null,
    children: [],
  })
const adminUpdateMenuItemMock = vi.fn().mockResolvedValue({
    id: 'item-id',
    menuId: 'menu-id',
    parentId: null,
    title: 'Item',
    url: null,
    icon: null,
    target: null,
    external: null,
    order: 0,
    meta: null,
    isVisible: true,
    isPublished: true,
    locale: null,
    createdAt: null,
    updatedAt: null,
    children: [],
  })
const adminDeleteMenuItemMock = vi.fn().mockResolvedValue(undefined)

const adminNavigationServiceStub: IAdminNavigationService = {
  listMenus: adminListMenusMock,
  getMenu: adminGetMenuMock,
  createMenu: adminCreateMenuMock,
  updateMenu: adminUpdateMenuMock,
  deleteMenu: adminDeleteMenuMock,
  listMenuItems: adminListMenuItemsMock,
  createMenuItem: adminCreateMenuItemMock,
  updateMenuItem: adminUpdateMenuItemMock,
  deleteMenuItem: adminDeleteMenuItemMock,
}

const authenticatorBase: Omit<AdminAuthenticatorCatalogRecord, 'id' | 'label' | 'factorType'> = {
  description: '',
  issuer: null,
  helper: null,
  docsUrl: null,
  tags: ['totp'],
  metadata: null,
  sortOrder: 0,
  isArchived: false,
  createdAt: null,
  updatedAt: null,
  archivedAt: null,
  archivedBy: null,
}

const authenticatorFixtures: AdminAuthenticatorCatalogRecord[] = [
  {
    ...authenticatorBase,
    id: 'google',
    label: 'Google Authenticator',
    factorType: 'TOTP',
    helper: 'Use the Google Authenticator app.',
    tags: ['totp', 'recommended'],
    sortOrder: 1,
  },
  {
    ...authenticatorBase,
    id: 'authy',
    label: 'Authy',
    factorType: 'TOTP',
    helper: 'Authy supports multi-device sync.',
    sortOrder: 2,
  },
  {
    ...authenticatorBase,
    id: 'backup_codes',
    label: 'Backup codes',
    factorType: 'BACKUP_CODES',
    isArchived: true,
    sortOrder: 99,
  },
]

const listAuthenticatorsMock = vi.fn().mockResolvedValue(authenticatorFixtures)
const createAuthenticatorMock = vi.fn().mockImplementation(async (input) => ({
  ...authenticatorBase,
  id: input.id,
  label: input.label,
  factorType: input.factorType,
  description: input.description ?? '',
  issuer: input.issuer ?? null,
  helper: input.helper ?? null,
  docsUrl: input.docsUrl ?? null,
  tags: input.tags ?? null,
  metadata: input.metadata ?? null,
  sortOrder: input.sortOrder ?? 0,
  isArchived: false,
  createdAt: null,
  updatedAt: null,
  archivedAt: null,
  archivedBy: null,
}))
const updateAuthenticatorMock = vi.fn().mockImplementation(async (id, input) => ({
  ...authenticatorBase,
  id,
  label: input.label ?? 'Updated',
  factorType: (input.factorType ?? 'TOTP') as AdminAuthenticatorCatalogRecord['factorType'],
  description: input.description ?? '',
  issuer: input.issuer ?? null,
  helper: input.helper ?? null,
  docsUrl: input.docsUrl ?? null,
  tags: input.tags ?? null,
  metadata: input.metadata ?? null,
  sortOrder: typeof input.sortOrder === 'number' ? input.sortOrder : 0,
  isArchived: false,
  createdAt: null,
  updatedAt: null,
  archivedAt: null,
  archivedBy: null,
}))
const archiveAuthenticatorMock = vi.fn().mockResolvedValue(undefined)
const restoreAuthenticatorMock = vi.fn().mockResolvedValue(undefined)

const adminAuthenticatorServiceStub: IAdminAuthenticatorCatalogService = {
  list: listAuthenticatorsMock,
  create: createAuthenticatorMock,
  update: updateAuthenticatorMock,
  archive: archiveAuthenticatorMock,
  restore: restoreAuthenticatorMock,
}

const createAdminService = (): IAdminService => ({
  settings: { loadSettings: loadSettingsMock, saveSettings: saveSettingsMock },
  navigation: adminNavigationServiceStub,
  authenticators: adminAuthenticatorServiceStub,
})

const loadNotificationSettingsMock = vi.fn().mockResolvedValue(DEFAULT_NOTIFICATION_SETTINGS)
const updateNotificationSettingsMock = vi.fn().mockResolvedValue(DEFAULT_NOTIFICATION_SETTINGS)

describe('AdminSettingsPage', () => {
  beforeEach(() => {
    saveSettingsMock.mockClear()
    loadSettingsMock.mockClear()
    listNavigationMenusMock.mockClear()
    listNavigationMenusMock.mockResolvedValue([navigationMenuMock])
    getNavigationMenuMock.mockClear()
    getNavigationMenuMock.mockResolvedValue(navigationMenuMock)
    adminListMenusMock.mockClear()
    adminGetMenuMock.mockClear()
    adminCreateMenuMock.mockClear()
    adminUpdateMenuMock.mockClear()
    adminDeleteMenuMock.mockClear()
    adminListMenuItemsMock.mockClear()
    adminCreateMenuItemMock.mockClear()
    adminUpdateMenuItemMock.mockClear()
    adminDeleteMenuItemMock.mockClear()
    loadNotificationSettingsMock.mockClear()
    updateNotificationSettingsMock.mockClear()
    listAuthenticatorsMock.mockClear()
    listAuthenticatorsMock.mockResolvedValue(authenticatorFixtures)
    createAuthenticatorMock.mockClear()
    updateAuthenticatorMock.mockClear()
    archiveAuthenticatorMock.mockClear()
    restoreAuthenticatorMock.mockClear()
  })

  it('saves security settings including new thresholds', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
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
        admin: createAdminService(),
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

  it('renders route-based items as links', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })

    render(<AdminSettingsPage />, { wrapper })

    await waitFor(() => expect(getNavigationMenuMock).toHaveBeenCalled())

    const profileLink = await screen.findByRole('link', { name: /profile/i })
    expect(profileLink).toHaveAttribute('href', '/settings/account/profile')

    // Fallback to plain menu url still renders as link
    const overviewLink = await screen.findByRole('link', { name: /account overview/i })
    expect(overviewLink).toHaveAttribute('href', '/settings/account/overview')
  })

  it('keeps headings aligned with the selected nav item even when categories repeat', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })

    render(<AdminSettingsPage />, { wrapper })

    await waitFor(() => expect(getNavigationMenuMock).toHaveBeenCalled())

    const orgButton = await screen.findByRole('button', { name: /organization settings/i })
    fireEvent.click(orgButton)

    const heading = await screen.findByRole('heading', { level: 2, name: /organization settings/i })
    expect(heading).toBeInTheDocument()
  })

  it('renders the notifications outlet even when navigation metadata is unavailable', async () => {
    const emptyNavigationService: INavigationService = {
      listMenus: vi.fn().mockResolvedValue([]),
      getMenu: vi.fn().mockResolvedValue(null),
    }

    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
        navigation: emptyNavigationService,
        notifications: {
          loadSettings: loadNotificationSettingsMock,
          updateSettings: updateNotificationSettingsMock,
        },
      },
      withRouter: true,
      initialEntries: ['/settings/account/notifications'],
    })

    render(
      <Routes>
        <Route path="/settings" element={<AdminSettingsPage />}>
          <Route path="account/notifications" element={<NotificationsSettingsPage />} />
        </Route>
      </Routes>,
      { wrapper }
    )

    expect(await screen.findByRole('heading', { name: /notifications & alerts/i })).toBeInTheDocument()
  })

  it('shows authentication controls when selecting the nav entry', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })
    render(<AdminSettingsPage />, { wrapper })

    await waitFor(() => expect(getNavigationMenuMock).toHaveBeenCalled())
    const authButton = await screen.findByRole('button', { name: /authentication/i })
    fireEvent.click(authButton)
    await waitFor(() => expect(listAuthenticatorsMock).toHaveBeenCalled())

    expect(await screen.findByLabelText(/MFA enrollment policy/i)).toBeInTheDocument()
    expect(screen.getByText(/Authenticator catalog/i)).toBeInTheDocument()
  })

  it('adds authenticators and persists the new auth payload keys', async () => {
    loadSettingsMock.mockResolvedValueOnce({
      security: { ...DEFAULT_SECURITY_SETTINGS },
      auth: {
        mode: 'session',
        google: true,
        github: false,
        enforceMfa: 'optional',
        authenticators: ['google'],
      },
    })

    saveSettingsMock.mockClear()
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })
    render(<AdminSettingsPage />, { wrapper })

    await waitFor(() => expect(loadSettingsMock).toHaveBeenCalled())
    const authButton = await screen.findByRole('button', { name: /authentication/i })
    fireEvent.click(authButton)
    await waitFor(() => expect(listAuthenticatorsMock).toHaveBeenCalled())

    const policySelect = await screen.findByLabelText(/MFA enrollment policy/i)
    fireEvent.change(policySelect, { target: { value: 'required' } })

    const addSelect = await screen.findByLabelText(/Authenticator to add/i)
    fireEvent.change(addSelect, { target: { value: 'authy' } })
    const addButton = await screen.findByRole('button', { name: /add authenticator/i })
    fireEvent.click(addButton)

    const saveButton = await screen.findByRole('button', { name: /save authentication/i })
    fireEvent.click(saveButton)

    await waitFor(() => expect(saveSettingsMock).toHaveBeenCalled())
    const [category, entries] = saveSettingsMock.mock.calls.at(-1)!
    expect(category).toBe('auth')
    const typedEntries = entries as Array<{ key: string; value: unknown }>
    const policyEntry = typedEntries.find((entry) => entry.key === 'enforceMfa')
    const authenticatorsEntry = typedEntries.find((entry) => entry.key === 'authenticators')
    expect(policyEntry?.value).toBe('required')
    expect(authenticatorsEntry?.value).toEqual(['google', 'authy'])
  })

  it('creates catalog entries through the dialog', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })
    render(<AdminSettingsPage />, { wrapper })

    await waitFor(() => expect(getNavigationMenuMock).toHaveBeenCalled())
    const authButton = await screen.findByRole('button', { name: /authentication/i })
    fireEvent.click(authButton)
    await waitFor(() => expect(listAuthenticatorsMock).toHaveBeenCalled())

    const newButton = await screen.findByRole('button', { name: /new authenticator/i })
    fireEvent.click(newButton)

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(/Identifier/i), { target: { value: 'duo_mobile' } })
    fireEvent.change(within(dialog).getByLabelText(/Display label/i), { target: { value: 'Duo Mobile' } })
    fireEvent.change(within(dialog).getByLabelText(/Factor type/i), { target: { value: 'PUSH' } })
    fireEvent.change(within(dialog).getByLabelText(/Sort order/i), { target: { value: '7' } })
    fireEvent.change(within(dialog).getByLabelText(/Description/i), { target: { value: 'Duo mobile push' } })
    fireEvent.change(within(dialog).getByLabelText(/Issuer/i), { target: { value: 'Duo' } })
    fireEvent.change(within(dialog).getByLabelText(/Helper text/i), { target: { value: 'Install the Duo app before enabling push.' } })
    fireEvent.change(within(dialog).getByLabelText(/Docs URL/i), { target: { value: 'https://example.com/duo' } })
    fireEvent.change(within(dialog).getByLabelText(/Tags/i), { target: { value: 'push, recommended' } })
    fireEvent.change(within(dialog).getByLabelText(/Metadata/i), { target: { value: '{"platforms":["ios","android"]}' } })

    const createButton = within(dialog).getByRole('button', { name: /^create$/i })
    fireEvent.click(createButton)

    await waitFor(() => expect(createAuthenticatorMock).toHaveBeenCalledWith({
      id: 'duo_mobile',
      label: 'Duo Mobile',
      description: 'Duo mobile push',
      factorType: 'PUSH',
      issuer: 'Duo',
      helper: 'Install the Duo app before enabling push.',
      docsUrl: 'https://example.com/duo',
      tags: ['push', 'recommended'],
      metadata: { platforms: ['ios', 'android'] },
      sortOrder: 7,
    }))
  })

  it('shows metadata validation errors in the catalog dialog', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })
    render(<AdminSettingsPage />, { wrapper })

    await waitFor(() => expect(getNavigationMenuMock).toHaveBeenCalled())
    const authButton = await screen.findByRole('button', { name: /authentication/i })
    fireEvent.click(authButton)
    await waitFor(() => expect(listAuthenticatorsMock).toHaveBeenCalled())

    const newButton = await screen.findByRole('button', { name: /new authenticator/i })
    fireEvent.click(newButton)

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(/Identifier/i), { target: { value: 'invalid_meta' } })
    fireEvent.change(within(dialog).getByLabelText(/Display label/i), { target: { value: 'Invalid Metadata' } })
    fireEvent.change(within(dialog).getByLabelText(/Metadata/i), { target: { value: '{not valid json}' } })

    const createButton = within(dialog).getByRole('button', { name: /^create$/i })
    fireEvent.click(createButton)

    await screen.findByText(/metadata must be valid json/i)
    expect(createAuthenticatorMock).not.toHaveBeenCalled()
  })

  it('edits catalog entries through the dialog', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })
    render(<AdminSettingsPage />, { wrapper })

    await waitFor(() => expect(getNavigationMenuMock).toHaveBeenCalled())
    const authButton = await screen.findByRole('button', { name: /authentication/i })
    fireEvent.click(authButton)
    await waitFor(() => expect(listAuthenticatorsMock).toHaveBeenCalled())

    const catalogCard = await screen.findByTestId('catalog-entry-google')
    const editButton = within(catalogCard).getByRole('button', { name: /^edit$/i })
    fireEvent.click(editButton)

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(/Display label/i), { target: { value: 'Google Authenticator (legacy)' } })
    fireEvent.change(within(dialog).getByLabelText(/Helper text/i), { target: { value: 'Legacy instructions' } })
    fireEvent.change(within(dialog).getByLabelText(/Sort order/i), { target: { value: '5' } })

    const saveButton = within(dialog).getByRole('button', { name: /^save$/i })
    fireEvent.click(saveButton)

    await waitFor(() => expect(updateAuthenticatorMock).toHaveBeenCalledWith('google', expect.objectContaining({
      label: 'Google Authenticator (legacy)',
      helper: 'Legacy instructions',
      sortOrder: 5,
    })))
  })

  it('archives and restores catalog entries', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: createAdminService(),
        navigation: navigationServiceStub,
      },
      withRouter: true,
    })
    render(<AdminSettingsPage />, { wrapper })

    await waitFor(() => expect(getNavigationMenuMock).toHaveBeenCalled())
    const authButton = await screen.findByRole('button', { name: /authentication/i })
    fireEvent.click(authButton)
    await waitFor(() => expect(listAuthenticatorsMock).toHaveBeenCalled())

    const authyCard = await screen.findByTestId('catalog-entry-authy')
    const archiveButton = within(authyCard).getByRole('button', { name: /archive/i })
    fireEvent.click(archiveButton)
    await waitFor(() => expect(archiveAuthenticatorMock).toHaveBeenCalledWith('authy'))

    const showArchivedButton = await screen.findByRole('button', { name: /show archived/i })
    fireEvent.click(showArchivedButton)

    const archivedCard = await screen.findByTestId('catalog-entry-backup_codes-archived')
    const restoreButton = within(archivedCard).getByRole('button', { name: /restore/i })
    fireEvent.click(restoreButton)
    await waitFor(() => expect(restoreAuthenticatorMock).toHaveBeenCalledWith('backup_codes'))
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
              admin: createAdminService(),
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
