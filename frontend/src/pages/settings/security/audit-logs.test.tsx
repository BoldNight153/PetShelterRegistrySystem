import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'

import SecurityAuditLogsSettingsPage from './audit-logs'
import type { AuditTimelineEntry } from '@/services/interfaces/types'
import type { IAdminNavigationService } from '@/services/interfaces/admin.interface'
import { renderWithProviders } from '@/test-utils/renderWithProviders'
import {
  DEFAULT_AUDIT_ALERTS,
  DEFAULT_AUDIT_EXPORTS,
  DEFAULT_AUDIT_RETENTION,
  DEFAULT_AUDIT_REVIEWERS,
} from '@/types/audit-settings'

const sampleEntry: AuditTimelineEntry = {
  id: 'evt_1',
  action: 'auth.login',
  createdAt: new Date().toISOString(),
  description: 'User signed in successfully',
  severity: 'info',
  actor: { id: 'user_1', email: 'admin@example.com', name: 'Admin' },
  tags: ['auth'],
}

const refreshMock = vi.fn()
const useActivityHistoryMock = vi.fn().mockReturnValue({
  data: { items: [sampleEntry], total: 1, page: 1, pageSize: 25 },
  loading: false,
  error: null,
  refresh: refreshMock,
})

vi.mock('@/hooks/use-activity-history', () => ({
  useActivityHistory: (filters: unknown) => useActivityHistoryMock(filters),
}))

const loadSettingsMock = vi.fn().mockResolvedValue({
  audit: {
    retention: DEFAULT_AUDIT_RETENTION,
    exports: DEFAULT_AUDIT_EXPORTS,
    alerts: DEFAULT_AUDIT_ALERTS,
    reviewers: DEFAULT_AUDIT_REVIEWERS,
  },
})

const saveSettingsMock = vi.fn().mockResolvedValue(undefined)

const adminNavigationStub: IAdminNavigationService = {
  listMenus: vi.fn().mockResolvedValue([]),
  getMenu: vi.fn().mockResolvedValue(null),
  createMenu: vi.fn(),
  updateMenu: vi.fn(),
  deleteMenu: vi.fn(),
  listMenuItems: vi.fn().mockResolvedValue([]),
  createMenuItem: vi.fn(),
  updateMenuItem: vi.fn(),
  deleteMenuItem: vi.fn(),
}

function renderPage() {
  const { wrapper } = renderWithProviders(<div />, {
    services: {
      admin: {
        settings: {
          loadSettings: loadSettingsMock,
          saveSettings: saveSettingsMock,
        },
        navigation: adminNavigationStub,
      },
    },
  })
  return render(<SecurityAuditLogsSettingsPage />, { wrapper })
}

async function renderPageWithConsoleOpen() {
  const utils = renderPage()
  const openButton = await screen.findByRole('button', { name: /open live console/i })
  fireEvent.click(openButton)
  return utils
}

describe('SecurityAuditLogsSettingsPage', () => {
  beforeEach(() => {
    useActivityHistoryMock.mockClear()
    refreshMock.mockClear()
    loadSettingsMock.mockClear()
    saveSettingsMock.mockClear()
  })

  it('renders presets and timeline metrics', async () => {
    await renderPageWithConsoleOpen()

    expect(await screen.findByText(/audit log configuration/i)).toBeInTheDocument()
    expect(await screen.findByText(/Events in range/i)).toBeInTheDocument()
    expect(screen.getByText(/auth signals this page/i)).toBeInTheDocument()
  })

  it('applies preset filters when scope changes', async () => {
    await renderPageWithConsoleOpen()

    const rbacButton = await screen.findByRole('button', { name: /roles & privileges/i })
    fireEvent.click(rbacButton)

    const latestFilters = useActivityHistoryMock.mock.calls.at(-1)?.[0] as Record<string, unknown>
    expect(latestFilters).toMatchObject({ action: 'admin.users' })
  })

  it('allows clearing filters', async () => {
    await renderPageWithConsoleOpen()

    const searchInput = await screen.findByPlaceholderText(/action, actor/i)
    fireEvent.change(searchInput, { target: { value: 'critical' } })
    expect(useActivityHistoryMock.mock.calls.at(-1)?.[0]).toMatchObject({ q: 'critical' })

    const clearButton = screen.getByRole('button', { name: /clear custom filters/i })
    fireEvent.click(clearButton)

    const lastFilters = useActivityHistoryMock.mock.calls.at(-1)?.[0] as Record<string, unknown>
    expect(lastFilters.q).toBeUndefined()
  })
})
