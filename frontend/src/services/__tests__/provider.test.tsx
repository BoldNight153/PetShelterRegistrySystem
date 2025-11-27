import { render, screen, cleanup } from '@testing-library/react'
import { vi, test, expect } from 'vitest'
import { ServicesProvider } from '@/services/provider'
import { useServices } from '@/services/hooks'
import type { Services } from '@/services/defaults'
import type {
  IAdminNavigationService,
  AdminMenuRecord,
  AdminMenuItem,
  IAdminAuthenticatorCatalogService,
  AdminAuthenticatorCatalogRecord,
} from '@/services/interfaces/admin.interface'

function Consumer() {
  const s = useServices()
  const hasAdminSettings = typeof s.admin?.settings?.loadSettings === 'function'
  const hasSecurity = typeof s.security?.loadSnapshot === 'function'
  const hasNotifications = typeof s.notifications?.loadSettings === 'function'
  return <div data-testid="has-services">{hasAdminSettings && hasSecurity && hasNotifications ? 'ok' : 'no'}</div>
}

test('ServicesProvider provides default services and allows overrides', () => {
  render(
    <ServicesProvider>
      <Consumer />
    </ServicesProvider>
  )
  expect(screen.getByTestId('has-services')).toHaveTextContent('ok')

  // remove the first render before rendering again to avoid duplicate test ids
  cleanup()

  const fakeLoad = vi.fn(async () => ({}))
  const fakeSave = vi.fn(async () => ({}))
  const fakeMenuRecord: AdminMenuRecord = { id: 'menu-id', name: 'settings-main' }
  const fakeMenuItem: AdminMenuItem = { id: 'item-id', menuId: 'menu-id', title: 'Settings' }
  const fakeNavigation: IAdminNavigationService = {
    listMenus: vi.fn(async () => []),
    getMenu: vi.fn(async () => null),
    createMenu: vi.fn(async (input) => ({ ...fakeMenuRecord, name: input.name })),
    updateMenu: vi.fn(async () => fakeMenuRecord),
    deleteMenu: vi.fn(async () => undefined),
    listMenuItems: vi.fn(async () => []),
    createMenuItem: vi.fn(async () => fakeMenuItem),
    updateMenuItem: vi.fn(async () => fakeMenuItem),
    deleteMenuItem: vi.fn(async () => undefined),
  }
  const fakeAuthRecord: AdminAuthenticatorCatalogRecord = {
    id: 'mock',
    label: 'Mock',
    factorType: 'TOTP',
    description: null,
    issuer: null,
    helper: null,
    docsUrl: null,
    tags: null,
    metadata: null,
    sortOrder: null,
    isArchived: false,
    createdAt: null,
    updatedAt: null,
    archivedAt: null,
    archivedBy: null,
  }
  const fakeAuthenticators: IAdminAuthenticatorCatalogService = {
    list: vi.fn(async () => []),
    create: vi.fn(async () => fakeAuthRecord),
    update: vi.fn(async () => fakeAuthRecord),
    archive: vi.fn(async () => undefined),
    restore: vi.fn(async () => undefined),
  }
  const override = {
    admin: { settings: { loadSettings: fakeLoad, saveSettings: fakeSave }, navigation: fakeNavigation, authenticators: fakeAuthenticators },
  } satisfies Partial<Services>
  render(
    <ServicesProvider services={override}>
      <Consumer />
    </ServicesProvider>
  )
  expect(screen.getByTestId('has-services')).toHaveTextContent('ok')
})
