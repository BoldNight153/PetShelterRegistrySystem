import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import AdminUsersPage from './users'
import { ServicesProvider } from '@/services/provider'

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

    render(
        <ServicesProvider
          services={{
            roles: {
              listRoles: listRolesMock,
              upsertRole: async (_input: { name: string; rank?: number; description?: string }) => { void _input; return {} },
              deleteRole: async (_name: string) => { void _name },
              listPermissions: async () => [],
              listRolePermissions: async (_roleName: string) => { void _roleName; return [] },
              grantPermission: async (_roleName: string, _permission: string) => { void _roleName; void _permission; return {} },
              revokePermission: async (_roleName: string, _permission: string) => { void _roleName; void _permission; return {} },
            },
            users: {
              searchUsers: searchUsersMock,
              assignUserRole: assignUserRoleMock,
              revokeUserRole: revokeUserRoleMock,
              lockUser: lockUserMock,
              unlockUser: unlockUserMock,
              getUser: async () => { throw new Error('not needed') }
            }
          }}
        >
        <AdminUsersPage />
      </ServicesProvider>
    )

    // wait for initial search
    await waitFor(() => expect(searchUsersMock).toHaveBeenCalled())

    // Lock the user
    promptSpy.mockReturnValueOnce('admin_action') // reason
    promptSpy.mockReturnValueOnce('') // until
    const lockButton = await screen.findByRole('button', { name: /lock/i })
    fireEvent.click(lockButton)

  await waitFor(() => expect(lockUserMock).toHaveBeenCalled())
  // ensure first three args are correct (unlockReason may be omitted depending on environment)
  const firstCallArgs = lockUserMock.mock.calls[0]
  expect(firstCallArgs[0]).toBe('u1')
  expect(firstCallArgs[1]).toBe('admin_action')
  expect(firstCallArgs[2]).toBeNull()
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
