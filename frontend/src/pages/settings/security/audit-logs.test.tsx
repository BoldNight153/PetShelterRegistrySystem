import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import SecurityAuditLogsSettingsPage from './audit-logs'
import type { AuditTimelineEntry } from '@/services/interfaces/types'

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

describe('SecurityAuditLogsSettingsPage', () => {
  beforeEach(() => {
    useActivityHistoryMock.mockClear()
    refreshMock.mockClear()
  })

  it('renders presets and timeline metrics', () => {
    render(<SecurityAuditLogsSettingsPage />)

    expect(screen.getByText(/Audit logs & retention/i)).toBeInTheDocument()
    expect(screen.getByText(/Events in range/i)).toBeInTheDocument()
    expect(screen.getByText(/auth signals this page/i)).toBeInTheDocument()
  })

  it('applies preset filters when scope changes', () => {
    render(<SecurityAuditLogsSettingsPage />)

    const rbacButton = screen.getByRole('button', { name: /roles & privileges/i })
    fireEvent.click(rbacButton)

    const latestFilters = useActivityHistoryMock.mock.calls.at(-1)?.[0] as Record<string, unknown>
    expect(latestFilters).toMatchObject({ action: 'admin.users' })
  })

  it('allows clearing filters', () => {
    render(<SecurityAuditLogsSettingsPage />)

    const searchInput = screen.getByPlaceholderText(/action, actor/i)
    fireEvent.change(searchInput, { target: { value: 'critical' } })
    expect(useActivityHistoryMock.mock.calls.at(-1)?.[0]).toMatchObject({ q: 'critical' })

    const clearButton = screen.getByRole('button', { name: /clear custom filters/i })
    fireEvent.click(clearButton)

    const lastFilters = useActivityHistoryMock.mock.calls.at(-1)?.[0] as Record<string, unknown>
    expect(lastFilters.q).toBeUndefined()
  })
})
