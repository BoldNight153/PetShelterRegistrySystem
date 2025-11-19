import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { vi, describe, it, beforeEach, expect } from 'vitest'

import AdminNavigationBuilderPage from './navigation-builder'
import { renderWithProviders } from '@/test-utils/renderWithProviders'
import { defaultServices } from '@/services/defaults'
import type { AdminMenu } from '@/services/interfaces/admin.interface'

vi.mock('@/lib/auth-context', () => ({
  useAuth: () => ({ user: { email: 'admin@example.com', roles: ['admin'] } }),
}))

const baseMenu: AdminMenu = {
  id: 'menu-1',
  name: 'settings_main',
  title: 'Settings',
  description: 'Root settings menu',
  locale: 'en-US',
  isActive: true,
  createdAt: null,
  updatedAt: null,
  items: [
    {
      id: 'item-1',
      menuId: 'menu-1',
      parentId: null,
      title: 'General',
      url: '/settings/general',
      icon: 'Settings',
      target: null,
      external: false,
      order: 0,
      meta: { settingsCategory: 'general' },
      isVisible: true,
      isPublished: true,
      locale: null,
      createdAt: null,
      updatedAt: null,
      children: [],
    },
  ],
}

describe('AdminNavigationBuilderPage', () => {
  const listMenusMock = vi.fn().mockResolvedValue([baseMenu])
  const getMenuMock = vi.fn().mockResolvedValue(baseMenu)
  const createMenuMock = vi.fn().mockResolvedValue({ ...baseMenu })
  const updateMenuMock = vi.fn().mockResolvedValue({ ...baseMenu })
  const deleteMenuMock = vi.fn().mockResolvedValue(undefined)
  const createMenuItemMock = vi.fn().mockResolvedValue({
    id: 'item-2',
    menuId: 'menu-1',
    parentId: null,
    title: 'New Item',
    url: '/settings/new',
    icon: null,
    target: null,
    external: false,
    order: 1,
    meta: null,
    isVisible: true,
    isPublished: true,
    locale: null,
    createdAt: null,
    updatedAt: null,
  })
  const updateMenuItemMock = vi.fn().mockResolvedValue(baseMenu.items[0])
  const deleteMenuItemMock = vi.fn().mockResolvedValue(undefined)

  beforeEach(() => {
    listMenusMock.mockClear()
    getMenuMock.mockClear()
    createMenuMock.mockClear()
    updateMenuMock.mockClear()
    deleteMenuMock.mockClear()
    createMenuItemMock.mockClear()
    updateMenuItemMock.mockClear()
    deleteMenuItemMock.mockClear()
  })

  it('allows creating a top-level menu item', async () => {
    const { wrapper } = renderWithProviders(<div />, {
      services: {
        admin: {
          settings: defaultServices.admin.settings,
          navigation: {
            listMenus: listMenusMock,
            getMenu: getMenuMock,
            createMenu: createMenuMock,
            updateMenu: updateMenuMock,
            deleteMenu: deleteMenuMock,
            listMenuItems: async () => baseMenu.items,
            createMenuItem: createMenuItemMock,
            updateMenuItem: updateMenuItemMock,
            deleteMenuItem: deleteMenuItemMock,
          },
        },
      },
      withRouter: true,
  initialEntries: ['/admin/navigation-builder'],
    })

    render(<AdminNavigationBuilderPage />, { wrapper })

    await waitFor(() => expect(listMenusMock).toHaveBeenCalled())
    expect(await screen.findByText('General')).toBeInTheDocument()

    const addButton = screen.getByRole('button', { name: /add top-level item/i })
    fireEvent.click(addButton)

    const titleInput = await screen.findByLabelText('Title')
    fireEvent.change(titleInput, { target: { value: 'New Item' } })

    const urlInput = screen.getByLabelText('URL')
    fireEvent.change(urlInput, { target: { value: '/settings/new' } })

    const saveBtn = screen.getByRole('button', { name: /save item/i })
    fireEvent.click(saveBtn)

    await waitFor(() => expect(createMenuItemMock).toHaveBeenCalled())
    const [menuIdArg, inputArg] = createMenuItemMock.mock.calls[0]
    expect(menuIdArg).toBe('menu-1')
    expect(inputArg).toEqual(expect.objectContaining({ title: 'New Item', url: '/settings/new' }))
  })
})
