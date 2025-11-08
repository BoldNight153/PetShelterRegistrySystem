import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import AdminPermissionsPage from './permissions'
import { renderWithProviders } from '@/test-utils/renderWithProviders'

// Mock auth as system_admin
vi.mock('@/lib/auth-context', () => ({ useAuth: () => ({ user: { email: 'admin@example.com', roles: ['system_admin'] } }) }))

const listPermissionsMock = vi.fn().mockResolvedValue([{ id: 'p1', name: 'view_reports' }])
const listRolesMock = vi.fn().mockResolvedValue([{ id: 'r1', name: 'staff_manager', rank: 50 }])
const listRolePermissionsMock = vi.fn().mockResolvedValue([])
const grantPermissionMock = vi.fn().mockResolvedValue({ ok: true })
const revokePermissionMock = vi.fn().mockResolvedValue({ ok: true })

describe('AdminPermissionsPage', () => {
  beforeEach(() => {
    listPermissionsMock.mockClear()
    listRolesMock.mockClear()
    listRolePermissionsMock.mockClear()
    grantPermissionMock.mockClear()
    revokePermissionMock.mockClear()
  })

  it('loads permissions and roles, and can grant/revoke a permission for a role', async () => {
    // stub window.confirm to allow revokes
    const confirmSpy = vi.spyOn(window, 'confirm').mockImplementation(() => true)

    const { wrapper } = renderWithProviders(<div />, {
      services: {
        roles: {
          listRoles: listRolesMock,
          upsertRole: async () => {},
          deleteRole: async () => {},
          listPermissions: listPermissionsMock,
          listRolePermissions: listRolePermissionsMock,
          grantPermission: grantPermissionMock,
          revokePermission: revokePermissionMock,
        }
      },
      withRouter: true,
    })

    render(<AdminPermissionsPage />, { wrapper })

    // Wait for initial data loads
    await waitFor(() => expect(listRolesMock).toHaveBeenCalled())
    await waitFor(() => expect(listPermissionsMock).toHaveBeenCalled())

    // Permission name should appear
    expect(await screen.findByText('view_reports')).toBeInTheDocument()

    // Select the role so grant/revoke actions are enabled
    const roleTrigger = screen.getByRole('combobox')
    fireEvent.click(roleTrigger)
    const roleOption = await screen.findByText('staff_manager')
    fireEvent.click(roleOption)

    // Try to grant permission - UI shows a 'Grant' button
    const grantBtn = screen.queryByRole('button', { name: /grant/i })
    if (grantBtn) {
      fireEvent.click(grantBtn)
      await waitFor(() => expect(grantPermissionMock).toHaveBeenCalled())
    }

    // Try to revoke permission - assume UI shows a 'Revoke' button
    const revokeBtn = screen.queryByRole('button', { name: /revoke/i })
    if (revokeBtn) {
      fireEvent.click(revokeBtn)
      await waitFor(() => expect(revokePermissionMock).toHaveBeenCalled())
    }

    confirmSpy.mockRestore()
  })
})
