import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { vi, describe, it, expect, beforeEach } from 'vitest'
import AdminRolesPage from './roles'
import { renderWithProviders } from '@/test-utils/renderWithProviders'

// Mock auth as system_admin
vi.mock('@/lib/auth-context', () => ({ useAuth: () => ({ user: { email: 'admin@example.com', roles: ['system_admin'] } }) }))

const listRolesMock = vi.fn().mockResolvedValue([{ id: 'r1', name: 'staff_manager', rank: 50, description: 'manages staff' }])
const upsertRoleMock = vi.fn().mockResolvedValue({ ok: true })
const deleteRoleMock = vi.fn().mockResolvedValue({ ok: true })

describe('AdminRolesPage', () => {
  beforeEach(() => {
    listRolesMock.mockClear()
    upsertRoleMock.mockClear()
    deleteRoleMock.mockClear()
  })

  it('loads roles and supports create/update and delete', async () => {
    // Stub window.confirm and window.alert to keep test output quiet
    const confirmSpy = vi.spyOn(window, 'confirm').mockImplementation(() => true)
    const alertSpy = vi.spyOn(window, 'alert').mockImplementation(() => undefined)

    const { wrapper } = renderWithProviders(<div />, {
      services: {
        roles: {
          listRoles: listRolesMock,
          upsertRole: upsertRoleMock,
          deleteRole: deleteRoleMock,
          listPermissions: async () => [],
          listRolePermissions: async (_: string) => [],
          grantPermission: async () => {},
          revokePermission: async () => {},
        }
      },
      withRouter: true,
    })

    render(<AdminRolesPage />, { wrapper })

    // Wait for roles to load
    await waitFor(() => expect(listRolesMock).toHaveBeenCalled())
    expect(await screen.findByText('staff_manager')).toBeInTheDocument()

    // Fill form and save a new role
    const nameInput = screen.getByPlaceholderText('e.g. shelter_admin')
    const descriptionInput = screen.getByPlaceholderText('optional')
    fireEvent.change(nameInput, { target: { value: 'new_role' } })
    fireEvent.change(descriptionInput, { target: { value: 'a role' } })

    const saveBtn = screen.getByRole('button', { name: /save/i })
    fireEvent.click(saveBtn)

    await waitFor(() => expect(upsertRoleMock).toHaveBeenCalled())

    // Delete an existing role
    const deleteBtn = await screen.findByRole('button', { name: /delete/i })
    fireEvent.click(deleteBtn)
    await waitFor(() => expect(deleteRoleMock).toHaveBeenCalled())

    confirmSpy.mockRestore()
    alertSpy.mockRestore()
  })
})
