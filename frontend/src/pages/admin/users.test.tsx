import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import AdminUsersPage from './users'

// Mock auth as system_admin
vi.mock('@/lib/auth-context', () => ({ useAuth: () => ({ user: { email: 'admin@example.com', roles: ['system_admin'] } }) }))

const listRolesMock = vi.fn().mockResolvedValue([{ id: '1', name: 'staff_manager', rank: 50 }])
const searchUsersMock = vi.fn().mockResolvedValue({ items: [
  { id: 'u1', email: 'user1@example.com', name: 'User One', roles: [], lock: null }
], total: 1, page: 1, pageSize: 20 })
const assignUserRoleMock = vi.fn().mockResolvedValue({ ok: true })
const revokeUserRoleMock = vi.fn().mockResolvedValue({ ok: true })
const lockUserMock = vi.fn().mockResolvedValue({ ok: true })
const unlockUserMock = vi.fn().mockResolvedValue({ ok: true })

vi.mock('@/lib/api', () => ({
  listRoles: () => listRolesMock(),
  searchUsers: (q?: string, page?: number, pageSize?: number) => searchUsersMock(q, page, pageSize),
  assignUserRole: (userId: string, roleName: string) => assignUserRoleMock(userId, roleName),
  revokeUserRole: (userId: string, roleName: string) => revokeUserRoleMock(userId, roleName),
  lockUser: (userId: string, reason: string, expiresAt?: string | null, notes?: string) => lockUserMock(userId, reason, expiresAt, notes),
  unlockUser: (userId: string, unlockReason?: string) => unlockUserMock(userId, unlockReason),
}))

describe('AdminUsersPage', () => {
  beforeEach(() => {
    listRolesMock.mockClear()
    searchUsersMock.mockClear()
    assignUserRoleMock.mockClear()
    revokeUserRoleMock.mockClear()
    lockUserMock.mockClear()
    unlockUserMock.mockClear()
  })

  it('loads and displays users, and supports lock/unlock', async () => {
    // Mock window.prompt for lock/unlock dialogs
    const promptSpy = vi.spyOn(window, 'prompt')

    render(<AdminUsersPage />)

    // wait for initial search
    await waitFor(() => expect(searchUsersMock).toHaveBeenCalled())

    // Lock the user
    promptSpy.mockReturnValueOnce('admin_action') // reason
    promptSpy.mockReturnValueOnce('') // until
    const lockButton = await screen.findByRole('button', { name: /lock/i })
    fireEvent.click(lockButton)

    await waitFor(() => expect(lockUserMock).toHaveBeenCalledWith('u1', 'admin_action', null, undefined))
    // UI should reflect locked state
    await screen.findByText(/locked:/i)

    // Unlock the user
    promptSpy.mockReturnValueOnce('') // unlock note optional
    const unlockButton = await screen.findByRole('button', { name: /unlock/i })
    fireEvent.click(unlockButton)
    await waitFor(() => expect(unlockUserMock).toHaveBeenCalledWith('u1', undefined))
    await screen.findByText(/active/i)

    promptSpy.mockRestore()
  })
})
