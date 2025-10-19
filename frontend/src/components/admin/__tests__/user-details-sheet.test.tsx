import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { describe, it, vi, expect } from 'vitest'
import UserDetailsSheet from '../user-details-sheet'
import { ServicesProvider } from '@/services/provider'

const user = { id: 'u1', email: 'user1@example.com', name: 'User One', roles: [], lock: null }

describe('UserDetailsSheet sessions', () => {
  it('shows sessions when service returns data', async () => {
    const listSessionsMock = vi.fn(async () => [{ id: 's1', createdAt: '2025-10-19T00:00:00Z', ip: '1.2.3.4', userAgent: 'ua' }])
    const getUserMock = vi.fn(async () => user)
    const listRolesMock = vi.fn(async () => [])
    const listRolePermissionsMock = vi.fn(async () => [])

    render(
      <ServicesProvider services={{ users: { searchUsers: async () => ({ items: [], total: 0, page: 1, pageSize: 20 }), getUser: getUserMock, assignUserRole: async () => ({}), revokeUserRole: async () => ({}), lockUser: async () => ({}), unlockUser: async () => ({}), listSessions: listSessionsMock }, roles: { listRoles: listRolesMock, listPermissions: async () => [], listRolePermissions: listRolePermissionsMock, upsertRole: async () => ({}), deleteRole: async () => {}, grantPermission: async () => ({}), revokePermission: async () => ({}) } }}>
        <UserDetailsSheet userId={user.id} open={true} onOpenChange={() => {}} />
      </ServicesProvider>
    )

    await waitFor(() => expect(getUserMock).toHaveBeenCalled())
    // sessions list should appear
    await waitFor(() => expect(listSessionsMock).toHaveBeenCalled())
    expect(await screen.findByText('s1')).toBeTruthy()
  })

  it('shows not-available message when service throws 404', async () => {
    const listSessionsMock = vi.fn(async () => { throw { status: 404 } })
    const getUserMock = vi.fn(async () => user)
    const listRolesMock = vi.fn(async () => [])
    const listRolePermissionsMock = vi.fn(async () => [])

    render(
      <ServicesProvider services={{ users: { searchUsers: async () => ({ items: [], total: 0, page: 1, pageSize: 20 }), getUser: getUserMock, assignUserRole: async () => ({}), revokeUserRole: async () => ({}), lockUser: async () => ({}), unlockUser: async () => ({}), listSessions: listSessionsMock }, roles: { listRoles: listRolesMock, listPermissions: async () => [], listRolePermissions: listRolePermissionsMock, upsertRole: async () => ({}), deleteRole: async () => {}, grantPermission: async () => ({}), revokePermission: async () => ({}) } }}>
        <UserDetailsSheet userId={user.id} open={true} onOpenChange={() => {}} />
      </ServicesProvider>
    )

    await waitFor(() => expect(getUserMock).toHaveBeenCalled())
    await waitFor(() => expect(listSessionsMock).toHaveBeenCalled())
    expect(await screen.findByText(/Session listing not available on this server/i)).toBeInTheDocument()
  })
})

describe('UserDetailsSheet actions', () => {
  it('locks and unlocks a user via prompts', async () => {
    const getUserMock = vi.fn(async () => ({ ...user, lock: null }))
    const lockUserMock = vi.fn(async () => ({}))
    const unlockUserMock = vi.fn(async () => ({}))
    const listRolesMock = vi.fn(async () => [])
    const listRolePermissionsMock = vi.fn(async () => [])

    const promptSpy = vi.spyOn(window, 'prompt')
    promptSpy.mockReturnValueOnce('admin_action') // lock reason
    promptSpy.mockReturnValueOnce('') // until blank

    render(
      <ServicesProvider services={{ users: { searchUsers: async () => ({ items: [], total: 0, page: 1, pageSize: 20 }), getUser: getUserMock, assignUserRole: async () => ({}), revokeUserRole: async () => ({}), lockUser: lockUserMock, unlockUser: unlockUserMock, listSessions: async () => [] }, roles: { listRoles: listRolesMock, listPermissions: async () => [], listRolePermissions: listRolePermissionsMock, upsertRole: async () => ({}), deleteRole: async () => {}, grantPermission: async () => ({}), revokePermission: async () => ({}) } }}>
        <UserDetailsSheet userId={user.id} open={true} onOpenChange={() => {}} />
      </ServicesProvider>
    )

    // wait for initial load
    await waitFor(() => expect(getUserMock).toHaveBeenCalled())

    // Click Lock button in footer (rendered when user present)
    const lockBtn = await screen.findByRole('button', { name: /lock/i })
    lockBtn.click()
    await waitFor(() => expect(lockUserMock).toHaveBeenCalled())
    // Unlock flow
    promptSpy.mockReturnValueOnce('')
    const unlockBtn = await screen.findByRole('button', { name: /unlock/i })
    unlockBtn.click()
    await waitFor(() => expect(unlockUserMock).toHaveBeenCalled())
    promptSpy.mockRestore()
  })

  it('assigns and revokes a role', async () => {
    const getUserMock = vi.fn(async () => ({ ...user, roles: [] }))
    const assignUserRoleMock = vi.fn(async () => ({}))
    const revokeUserRoleMock = vi.fn(async () => ({}))
    const listRolesMock = vi.fn(async () => [{ id: 'r1', name: 'staff', rank: 10 }])
    const listRolePermissionsMock = vi.fn(async () => [])

    render(
      <ServicesProvider services={{ users: { searchUsers: async () => ({ items: [], total: 0, page: 1, pageSize: 20 }), getUser: getUserMock, assignUserRole: assignUserRoleMock, revokeUserRole: revokeUserRoleMock, lockUser: async () => ({}), unlockUser: async () => ({}), listSessions: async () => [] }, roles: { listRoles: listRolesMock, listPermissions: async () => [], listRolePermissions: listRolePermissionsMock, upsertRole: async () => ({}), deleteRole: async () => {}, grantPermission: async () => ({}), revokePermission: async () => ({}) } }}>
        <UserDetailsSheet userId={user.id} open={true} onOpenChange={() => {}} />
      </ServicesProvider>
    )

    await waitFor(() => expect(getUserMock).toHaveBeenCalled())
  // Open the Radix select and click the role item
  const trigger = await screen.findByRole('button', { name: /select role|select role/i })
  if (trigger) fireEvent.click(trigger)
  // Click the role item by text
  const roleItem = await screen.findByText('staff')
  fireEvent.click(roleItem)
  // Click assign
  const assignBtn = await screen.findByRole('button', { name: /assign/i })
  fireEvent.click(assignBtn)
  await waitFor(() => expect(assignUserRoleMock).toHaveBeenCalled())

    // Revoke: find revoke button rendered with role tag (after optimistic update it should exist). Click the revoke button (it has text 'Revoke')
    const revokeBtn = await screen.findByText(/revoke/i)
    revokeBtn.click()
    await waitFor(() => expect(revokeUserRoleMock).toHaveBeenCalled())
  })
})
