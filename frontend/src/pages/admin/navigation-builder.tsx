import * as React from 'react'
import { useSearchParams } from 'react-router-dom'
import { Loader2, Pencil, Plus, RefreshCcw, ShieldAlert, Trash2 } from 'lucide-react'
import { useMutation, useQueryClient } from '@tanstack/react-query'

import { useAuth } from '@/lib/auth-context'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { cn } from '@/lib/utils'
import { useServices } from '@/services/hooks'
import {
  ADMIN_MENU_DETAIL_QUERY_KEY,
  ADMIN_MENUS_QUERY_KEY,
  useAdminMenu,
  useAdminMenus,
} from '@/services/hooks/navigationAdmin'
import type {
  AdminMenu,
  AdminMenuRecord,
  AdminMenuItem,
  CreateAdminMenuInput,
  UpdateAdminMenuInput,
  CreateAdminMenuItemInput,
  UpdateAdminMenuItemInput,
} from '@/services/interfaces/admin.interface'
import type { JsonValue } from '@/services/interfaces/types'

const DEFAULT_MENU_FORM = {
  name: '',
  title: '',
  description: '',
  locale: '',
  isActive: true,
}

const DEFAULT_ITEM_FORM = {
  title: '',
  url: '',
  icon: '',
  target: '',
  external: false,
  order: '',
  metaRaw: '',
  isVisible: true,
  isPublished: true,
  locale: '',
}

type MenuDialogState =
  | { mode: 'create' }
  | { mode: 'edit'; menu: AdminMenu }

type ItemDialogState =
  | { mode: 'create'; parentId: string | null }
  | { mode: 'edit'; item: AdminMenuItem }

function normalizeMeta(meta: JsonValue | undefined): string {
  if (meta === undefined || meta === null) return ''
  try {
    if (typeof meta === 'string') return meta
    return JSON.stringify(meta, null, 2)
  } catch {
    return ''
  }
}

function boolFromCheckbox(value: boolean | 'indeterminate'): boolean {
  return value === true
}

function buildMenuPayload(form: typeof DEFAULT_MENU_FORM): CreateAdminMenuInput {
  const title = form.title.trim()
  const description = form.description.trim()
  const locale = form.locale.trim()
  return {
    name: form.name.trim(),
    title: title ? title : null,
    description: description ? description : null,
    locale: locale ? locale : null,
    isActive: form.isActive,
  }
}

function buildMenuUpdatePayload(form: typeof DEFAULT_MENU_FORM): UpdateAdminMenuInput {
  const title = form.title.trim()
  const description = form.description.trim()
  const locale = form.locale.trim()
  return {
    title: title ? title : null,
    description: description ? description : null,
    locale: locale ? locale : null,
    isActive: form.isActive,
  }
}

function buildItemPayload(
  form: typeof DEFAULT_ITEM_FORM,
  parentId: string | null | undefined,
): { payload: CreateAdminMenuItemInput | UpdateAdminMenuItemInput; error?: string } {
  if (!form.title.trim()) {
    return { payload: {} as CreateAdminMenuItemInput, error: 'Title is required.' }
  }

  const orderValue = form.order.trim()
  let order: number | null = null
  if (orderValue) {
    const parsed = Number(orderValue)
    if (Number.isNaN(parsed)) {
      return { payload: {} as CreateAdminMenuItemInput, error: 'Order must be a number.' }
    }
    order = parsed
  }

  let meta: JsonValue | null | undefined = undefined
  const metaValue = form.metaRaw.trim()
  if (metaValue) {
    try {
      meta = JSON.parse(metaValue) as JsonValue
    } catch {
      return { payload: {} as CreateAdminMenuItemInput, error: 'Meta must be valid JSON.' }
    }
  } else {
    meta = null
  }

  const url = form.url.trim()
  const icon = form.icon.trim()
  const target = form.target.trim()
  const locale = form.locale.trim()

  const payload: CreateAdminMenuItemInput = {
    title: form.title.trim(),
    url: url ? url : null,
    icon: icon ? icon : null,
    target: target ? target : null,
    external: form.external,
    order,
    meta,
    parentId: parentId ?? null,
    isVisible: form.isVisible,
    isPublished: form.isPublished,
    locale: locale ? locale : null,
  }

  return { payload }
}

function AdminNavigationBuilderPage() {
  const { user } = useAuth()
  const services = useServices()
  const queryClient = useQueryClient()
  const [searchParams, setSearchParams] = useSearchParams()
  const [menuDialog, setMenuDialog] = React.useState<MenuDialogState | null>(null)
  const [itemDialog, setItemDialog] = React.useState<ItemDialogState | null>(null)
  const [menuForm, setMenuForm] = React.useState(DEFAULT_MENU_FORM)
  const [itemForm, setItemForm] = React.useState(DEFAULT_ITEM_FORM)
  const [menuDialogError, setMenuDialogError] = React.useState<string | null>(null)
  const [itemDialogError, setItemDialogError] = React.useState<string | null>(null)
  const [bannerError, setBannerError] = React.useState<string | null>(null)

  const menuParam = searchParams.get('menu')

  const {
    data: menus,
    isLoading: menusLoading,
    error: menusError,
  } = useAdminMenus()

  const {
    data: selectedMenu,
    isLoading: selectedMenuLoading,
    error: selectedMenuError,
  } = useAdminMenu(menuParam)

  const createMenuMutation = useMutation<AdminMenuRecord, Error, CreateAdminMenuInput>({
    mutationFn: (input: CreateAdminMenuInput) => services.admin.navigation.createMenu(input),
  })
  const updateMenuMutation = useMutation<AdminMenuRecord, Error, { id: string; input: UpdateAdminMenuInput }>({
    mutationFn: (args: { id: string; input: UpdateAdminMenuInput }) => services.admin.navigation.updateMenu(args.id, args.input),
  })
  const deleteMenuMutation = useMutation<void, Error, string>({
    mutationFn: (id: string) => services.admin.navigation.deleteMenu(id),
  })
  const createItemMutation = useMutation<AdminMenuItem, Error, { menuId: string; input: CreateAdminMenuItemInput }>({
    mutationFn: (args: { menuId: string; input: CreateAdminMenuItemInput }) =>
      services.admin.navigation.createMenuItem(args.menuId, args.input),
  })
  const updateItemMutation = useMutation<AdminMenuItem, Error, { id: string; input: UpdateAdminMenuItemInput }>({
    mutationFn: (args: { id: string; input: UpdateAdminMenuItemInput }) =>
      services.admin.navigation.updateMenuItem(args.id, args.input),
  })
  const deleteItemMutation = useMutation<void, Error, string>({
    mutationFn: (id: string) => services.admin.navigation.deleteMenuItem(id),
  })

  const canManageNavigation = React.useMemo(
    () => Boolean(user?.roles?.some((role) => role === 'admin' || role === 'system_admin')),
    [user?.roles],
  )

  React.useEffect(() => {
    if (!menus || menus.length === 0) return
    if (menuParam && menus.some((menu) => menu.name === menuParam)) return
    const next = menus[0].name
    const params = new URLSearchParams(searchParams)
    params.set('menu', next)
    setSearchParams(params, { replace: true })
  }, [menus, menuParam, searchParams, setSearchParams])

  React.useEffect(() => {
    if (!menuDialog) {
      setMenuForm(DEFAULT_MENU_FORM)
      setMenuDialogError(null)
      return
    }
    if (menuDialog.mode === 'create') {
      setMenuForm(DEFAULT_MENU_FORM)
      setMenuDialogError(null)
      return
    }
    const menu = menuDialog.menu
    setMenuForm({
      name: menu.name,
      title: menu.title ?? '',
      description: menu.description ?? '',
      locale: menu.locale ?? '',
      isActive: menu.isActive !== false,
    })
    setMenuDialogError(null)
  }, [menuDialog])

  React.useEffect(() => {
    if (!itemDialog) {
      setItemForm(DEFAULT_ITEM_FORM)
      setItemDialogError(null)
      return
    }
    if (itemDialog.mode === 'create') {
      setItemForm(DEFAULT_ITEM_FORM)
      setItemDialogError(null)
      return
    }
    const item = itemDialog.item
    setItemForm({
      title: item.title,
      url: item.url ?? '',
      icon: item.icon ?? '',
      target: item.target ?? '',
      external: Boolean(item.external),
      order: item.order !== null && item.order !== undefined ? String(item.order) : '',
      metaRaw: normalizeMeta(item.meta),
      isVisible: item.isVisible !== false,
      isPublished: item.isPublished !== false,
      locale: item.locale ?? '',
    })
    setItemDialogError(null)
  }, [itemDialog])

  const handleMenuSubmit = React.useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault()
      if (!menuDialog) return
      setMenuDialogError(null)
      setBannerError(null)

      try {
        if (menuDialog.mode === 'create') {
          if (!menuForm.name.trim()) {
            setMenuDialogError('Menu API name is required.')
            return
          }
          const payload = buildMenuPayload(menuForm)
          const created = await createMenuMutation.mutateAsync(payload)
          await queryClient.invalidateQueries({ queryKey: ADMIN_MENUS_QUERY_KEY })
          setMenuDialog(null)
          const params = new URLSearchParams(searchParams)
          params.set('menu', created.name)
          setSearchParams(params, { replace: true })
        } else {
          const payload = buildMenuUpdatePayload(menuForm)
          await updateMenuMutation.mutateAsync({ id: menuDialog.menu.id, input: payload })
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: ADMIN_MENUS_QUERY_KEY }),
            queryClient.invalidateQueries({ queryKey: [...ADMIN_MENU_DETAIL_QUERY_KEY, menuDialog.menu.name] }),
          ])
          setMenuDialog(null)
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Operation failed.'
        setMenuDialogError(message)
      }
    },
    [
      menuDialog,
      menuForm,
      createMenuMutation,
      queryClient,
      searchParams,
      setSearchParams,
      updateMenuMutation,
    ],
  )

  const handleDeleteMenu = React.useCallback(
    async (menu: AdminMenu) => {
      if (!window.confirm(`Delete menu "${menu.title || menu.name}"? This cannot be undone.`)) {
        return
      }
      setBannerError(null)
      try {
        await deleteMenuMutation.mutateAsync(menu.id)
        await queryClient.invalidateQueries({ queryKey: ADMIN_MENUS_QUERY_KEY })
        if (menuParam === menu.name) {
          const remaining = menus?.filter((m) => m.name !== menu.name) ?? []
          const params = new URLSearchParams(searchParams)
          if (remaining.length > 0) {
            params.set('menu', remaining[0].name)
          } else {
            params.delete('menu')
          }
          setSearchParams(params, { replace: true })
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to delete menu.'
        setBannerError(message)
      }
    },
    [deleteMenuMutation, menuParam, menus, queryClient, searchParams, setSearchParams],
  )

  const handleItemSubmit = React.useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault()
      if (!itemDialog || !selectedMenu) return
      setItemDialogError(null)
      setBannerError(null)

      const parentId = itemDialog.mode === 'create' ? itemDialog.parentId : itemDialog.item.parentId
      const { payload, error } = buildItemPayload(itemForm, parentId)
      if (error) {
        setItemDialogError(error)
        return
      }

      try {
        if (itemDialog.mode === 'create') {
          await createItemMutation.mutateAsync({ menuId: selectedMenu.id, input: payload as CreateAdminMenuItemInput })
        } else {
          await updateItemMutation.mutateAsync({ id: itemDialog.item.id, input: payload as UpdateAdminMenuItemInput })
        }
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ADMIN_MENUS_QUERY_KEY }),
          queryClient.invalidateQueries({ queryKey: [...ADMIN_MENU_DETAIL_QUERY_KEY, selectedMenu.name] }),
        ])
        setItemDialog(null)
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to save menu item.'
        setItemDialogError(message)
      }
    },
    [
      itemDialog,
      selectedMenu,
      itemForm,
      createItemMutation,
      updateItemMutation,
      queryClient,
    ],
  )

  const handleDeleteItem = React.useCallback(
    async (item: AdminMenuItem) => {
      if (!selectedMenu) return
      if (!window.confirm(`Delete "${item.title}" and all of its children?`)) {
        return
      }
      setBannerError(null)
      try {
        await deleteItemMutation.mutateAsync(item.id)
        await Promise.all([
          queryClient.invalidateQueries({ queryKey: ADMIN_MENUS_QUERY_KEY }),
          queryClient.invalidateQueries({ queryKey: [...ADMIN_MENU_DETAIL_QUERY_KEY, selectedMenu.name] }),
        ])
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to delete menu item.'
        setBannerError(message)
      }
    },
    [deleteItemMutation, queryClient, selectedMenu],
  )

  if (!canManageNavigation) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 text-red-600 dark:text-red-400">
          <ShieldAlert className="size-5" />
          <span>Access denied</span>
        </div>
        <p className="text-sm text-muted-foreground mt-2">
          Only administrators can manage navigation menus.
        </p>
      </div>
    )
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold">Navigation builder</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Configure admin menus and control which links appear in the application.
          </p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            queryClient.invalidateQueries({ queryKey: ADMIN_MENUS_QUERY_KEY })
            if (menuParam) {
              queryClient.invalidateQueries({ queryKey: [...ADMIN_MENU_DETAIL_QUERY_KEY, menuParam] })
            }
          }}
          aria-label="Refresh menus"
        >
          <RefreshCcw className="size-4" />
          Refresh
        </Button>
      </div>

      {bannerError ? (
        <Alert variant="destructive">
          <AlertTitle>Something went wrong</AlertTitle>
          <AlertDescription>{bannerError}</AlertDescription>
        </Alert>
      ) : null}

      {menusError ? (
        <Alert variant="destructive">
          <AlertTitle>Unable to load menus</AlertTitle>
          <AlertDescription>
            {menusError instanceof Error ? menusError.message : 'An unexpected error occurred while loading menus.'}
          </AlertDescription>
        </Alert>
      ) : null}

      {selectedMenuError && menuParam ? (
        <Alert variant="destructive">
          <AlertTitle>Unable to load menu</AlertTitle>
          <AlertDescription>
            {selectedMenuError instanceof Error
              ? selectedMenuError.message
              : 'An unexpected error occurred while loading the selected menu.'}
          </AlertDescription>
        </Alert>
      ) : null}

      <div className="flex flex-col lg:flex-row gap-6">
        <aside className="w-full lg:w-72 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">Menus</h2>
            <Button size="sm" onClick={() => setMenuDialog({ mode: 'create' })}>
              <Plus className="size-4" />
              New menu
            </Button>
          </div>

          {menusLoading ? (
            <p className="text-sm text-muted-foreground">Loading menus…</p>
          ) : menus && menus.length > 0 ? (
            <ul className="space-y-2">
              {menus.map((menu) => {
                const isActiveMenu = menu.name === menuParam
                return (
                  <li key={menu.id} className="border rounded-md">
                    <div
                      className={cn(
                        'flex items-center justify-between gap-2 px-3 py-2 text-left transition',
                        isActiveMenu
                          ? 'bg-accent text-accent-foreground'
                          : 'hover:bg-accent/40 hover:text-accent-foreground',
                      )}
                    >
                      <button
                        type="button"
                        className="flex-1 text-left"
                        onClick={() => {
                          const params = new URLSearchParams(searchParams)
                          params.set('menu', menu.name)
                          setSearchParams(params, { replace: true })
                        }}
                      >
                        <div className="font-medium truncate">{menu.title || menu.name}</div>
                        <div className="text-xs text-muted-foreground truncate">
                          API name: {menu.name}
                        </div>
                        {menu.description ? (
                          <div className="text-xs text-muted-foreground break-words whitespace-pre-line">
                            {menu.description}
                          </div>
                        ) : null}
                      </button>
                      <div className="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Edit menu ${menu.title || menu.name}`}
                          onClick={() => setMenuDialog({ mode: 'edit', menu })}
                        >
                          <Pencil className="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label={`Delete menu ${menu.title || menu.name}`}
                          onClick={() => handleDeleteMenu(menu)}
                          disabled={deleteMenuMutation.isPending}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </div>
                    </div>
                  </li>
                )
              })}
            </ul>
          ) : (
            <p className="text-sm text-muted-foreground">No menus found. Create one to get started.</p>
          )}
        </aside>

        <section className="flex-1 space-y-5">
          {selectedMenuLoading ? (
            <div className="flex items-center gap-2 text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              Loading menu…
            </div>
          ) : !selectedMenu ? (
            <div className="rounded border border-dashed p-6 text-center text-sm text-muted-foreground">
              Select a menu to edit its navigation structure.
            </div>
          ) : (
            <div className="space-y-5">
              <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <h2 className="text-xl font-semibold">{selectedMenu.title || selectedMenu.name}</h2>
                  <p className="text-sm text-muted-foreground">
                    {selectedMenu.description || 'Manage the menu items for this navigation tree.'}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => setMenuDialog({ mode: 'edit', menu: selectedMenu })}>
                    <Pencil className="size-4" />
                    Edit menu
                  </Button>
                  <Button size="sm" onClick={() => setItemDialog({ mode: 'create', parentId: null })}>
                    <Plus className="size-4" />
                    Add top-level item
                  </Button>
                </div>
              </div>

              {selectedMenu.items && selectedMenu.items.length > 0 ? (
                <div className="space-y-3">
                  <MenuItemTree
                    items={selectedMenu.items}
                    onAddChild={(item) => setItemDialog({ mode: 'create', parentId: item.id })}
                    onEdit={(item) => setItemDialog({ mode: 'edit', item })}
                    onDelete={handleDeleteItem}
                  />
                </div>
              ) : (
                <div className="rounded border border-dashed p-6 text-center text-sm text-muted-foreground">
                  This menu has no items yet. Add your first link to start building the tree.
                </div>
              )}
            </div>
          )}
        </section>
      </div>

      <Dialog open={Boolean(menuDialog)} onOpenChange={(open) => { if (!open) setMenuDialog(null) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{menuDialog?.mode === 'edit' ? 'Edit menu' : 'Create menu'}</DialogTitle>
            <DialogDescription>
              {menuDialog?.mode === 'edit'
                ? 'Update the metadata for this menu.'
                : 'Provide a unique API name and optional metadata for the new menu.'}
            </DialogDescription>
          </DialogHeader>
          {menuDialogError ? (
            <Alert variant="destructive">
              <AlertTitle>Unable to save</AlertTitle>
              <AlertDescription>{menuDialogError}</AlertDescription>
            </Alert>
          ) : null}
          <form className="space-y-4" onSubmit={handleMenuSubmit}>
            {menuDialog?.mode === 'create' ? (
              <div className="space-y-2">
                <Label htmlFor="menu-name">API name</Label>
                <Input
                  id="menu-name"
                  value={menuForm.name}
                  onChange={(event) => setMenuForm((prev) => ({ ...prev, name: event.target.value }))}
                  placeholder="settings_main"
                  required
                />
                <p className="text-xs text-muted-foreground">Used when requesting the menu via API. Must be unique.</p>
              </div>
            ) : menuDialog ? (
              <div className="space-y-1">
                <Label>API name</Label>
                <div className="rounded border bg-muted px-3 py-2 text-sm">
                  {menuDialog.menu.name}
                </div>
              </div>
            ) : null}
            <div className="space-y-2">
              <Label htmlFor="menu-title">Display title</Label>
              <Input
                id="menu-title"
                value={menuForm.title}
                onChange={(event) => setMenuForm((prev) => ({ ...prev, title: event.target.value }))}
                placeholder="Settings navigation"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="menu-description">Description</Label>
              <Textarea
                id="menu-description"
                value={menuForm.description}
                onChange={(event) => setMenuForm((prev) => ({ ...prev, description: event.target.value }))}
                placeholder="Optional description displayed to administrators"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="menu-locale">Locale (optional)</Label>
              <Input
                id="menu-locale"
                value={menuForm.locale}
                onChange={(event) => setMenuForm((prev) => ({ ...prev, locale: event.target.value }))}
                placeholder="en-US"
              />
            </div>
            <div className="flex items-center gap-2">
              <Checkbox
                id="menu-active"
                checked={menuForm.isActive}
                onCheckedChange={(checked) =>
                  setMenuForm((prev) => ({ ...prev, isActive: boolFromCheckbox(checked) }))
                }
              />
              <Label htmlFor="menu-active" className="m-0">
                Menu is active
              </Label>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setMenuDialog(null)}
                disabled={createMenuMutation.isPending || updateMenuMutation.isPending}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={createMenuMutation.isPending || updateMenuMutation.isPending}
              >
                {(createMenuMutation.isPending || updateMenuMutation.isPending) ? (
                  <>
                    <Loader2 className="size-4 animate-spin" /> Saving
                  </>
                ) : (
                  'Save changes'
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={Boolean(itemDialog)} onOpenChange={(open) => { if (!open) setItemDialog(null) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{itemDialog?.mode === 'edit' ? 'Edit menu item' : 'Add menu item'}</DialogTitle>
            <DialogDescription>
              {itemDialog?.mode === 'edit'
                ? 'Update the properties for this menu item.'
                : 'Configure the new menu link and optional display settings.'}
            </DialogDescription>
          </DialogHeader>
          {itemDialogError ? (
            <Alert variant="destructive">
              <AlertTitle>Unable to save</AlertTitle>
              <AlertDescription>{itemDialogError}</AlertDescription>
            </Alert>
          ) : null}
          <form className="space-y-4" onSubmit={handleItemSubmit}>
            <div className="space-y-2">
              <Label htmlFor="item-title">Title</Label>
              <Input
                id="item-title"
                value={itemForm.title}
                onChange={(event) => setItemForm((prev) => ({ ...prev, title: event.target.value }))}
                placeholder="Settings"
                required
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="item-url">URL</Label>
                <Input
                  id="item-url"
                  value={itemForm.url}
                  onChange={(event) => setItemForm((prev) => ({ ...prev, url: event.target.value }))}
                  placeholder="/settings/general"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="item-icon">Icon</Label>
                <Input
                  id="item-icon"
                  value={itemForm.icon}
                  onChange={(event) => setItemForm((prev) => ({ ...prev, icon: event.target.value }))}
                  placeholder="Settings"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="item-target">Target</Label>
                <Input
                  id="item-target"
                  value={itemForm.target}
                  onChange={(event) => setItemForm((prev) => ({ ...prev, target: event.target.value }))}
                  placeholder="_blank"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="item-order">Order</Label>
                <Input
                  id="item-order"
                  value={itemForm.order}
                  onChange={(event) => setItemForm((prev) => ({ ...prev, order: event.target.value }))}
                  placeholder="0"
                  inputMode="numeric"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-center gap-2">
                <Checkbox
                  id="item-external"
                  checked={itemForm.external}
                  onCheckedChange={(checked) =>
                    setItemForm((prev) => ({ ...prev, external: boolFromCheckbox(checked) }))
                  }
                />
                <Label htmlFor="item-external" className="m-0">
                  Open in new window / external link
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="item-visible"
                  checked={itemForm.isVisible}
                  onCheckedChange={(checked) =>
                    setItemForm((prev) => ({ ...prev, isVisible: boolFromCheckbox(checked) }))
                  }
                />
                <Label htmlFor="item-visible" className="m-0">
                  Visible in menu
                </Label>
              </div>
              <div className="flex items-center gap-2">
                <Checkbox
                  id="item-published"
                  checked={itemForm.isPublished}
                  onCheckedChange={(checked) =>
                    setItemForm((prev) => ({ ...prev, isPublished: boolFromCheckbox(checked) }))
                  }
                />
                <Label htmlFor="item-published" className="m-0">
                  Published
                </Label>
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="item-locale">Locale (optional)</Label>
              <Input
                id="item-locale"
                value={itemForm.locale}
                onChange={(event) => setItemForm((prev) => ({ ...prev, locale: event.target.value }))}
                placeholder="en-US"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="item-meta">Meta JSON</Label>
              <Textarea
                id="item-meta"
                value={itemForm.metaRaw}
                onChange={(event) => setItemForm((prev) => ({ ...prev, metaRaw: event.target.value }))}
                placeholder='{"settingsCategory": "general"}'
              />
              <p className="text-xs text-muted-foreground">
                Optional structured metadata stored with the menu item. Provide valid JSON.
              </p>
            </div>
            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setItemDialog(null)}
                disabled={createItemMutation.isPending || updateItemMutation.isPending}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={createItemMutation.isPending || updateItemMutation.isPending}
              >
                {(createItemMutation.isPending || updateItemMutation.isPending) ? (
                  <>
                    <Loader2 className="size-4 animate-spin" /> Saving
                  </>
                ) : (
                  'Save item'
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}

type MenuItemTreeProps = {
  items: AdminMenuItem[]
  depth?: number
  onAddChild: (item: AdminMenuItem) => void
  onEdit: (item: AdminMenuItem) => void
  onDelete: (item: AdminMenuItem) => void
}

function MenuItemTree({ items, depth = 0, onAddChild, onEdit, onDelete }: MenuItemTreeProps) {
  return (
    <ul className="space-y-2">
      {items.map((item) => (
        <li key={item.id}>
          <div
            className={cn(
              'border rounded-md bg-card px-3 py-2 shadow-xs',
              depth > 0 ? 'ml-4' : '',
            )}
          >
            <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
              <div className="flex-1">
                <div className="font-medium">{item.title}</div>
                <div className="text-xs text-muted-foreground space-x-2">
                  {item.url ? <span>{item.url}</span> : <span>No URL</span>}
                  {item.external ? <Badge variant="outline">External</Badge> : null}
                  {item.isVisible === false ? <Badge variant="destructive">Hidden</Badge> : null}
                  {item.isPublished === false ? <Badge variant="secondary">Draft</Badge> : null}
                </div>
                {item.meta && typeof item.meta === 'object' && !Array.isArray(item.meta) ? (
                  <div className="text-xs text-muted-foreground mt-1">
                    Meta keys: {Object.keys(item.meta).join(', ') || '—'}
                  </div>
                ) : null}
              </div>
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`Add child for ${item.title}`}
                  onClick={() => onAddChild(item)}
                >
                  <Plus className="size-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`Edit ${item.title}`}
                  onClick={() => onEdit(item)}
                >
                  <Pencil className="size-4" />
                </Button>
                <Button
                  variant="ghost"
                  size="icon"
                  aria-label={`Delete ${item.title}`}
                  onClick={() => onDelete(item)}
                >
                  <Trash2 className="size-4" />
                </Button>
              </div>
            </div>
          </div>
          {item.children && item.children.length > 0 ? (
            <div className="mt-2">
              <MenuItemTree
                items={item.children}
                depth={depth + 1}
                onAddChild={onAddChild}
                onEdit={onEdit}
                onDelete={onDelete}
              />
            </div>
          ) : null}
        </li>
      ))}
    </ul>
  )
}

export default AdminNavigationBuilderPage
