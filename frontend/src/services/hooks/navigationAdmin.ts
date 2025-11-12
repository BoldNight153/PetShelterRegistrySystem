import { useQuery, type UseQueryOptions } from '@tanstack/react-query'

import { useServices } from '@/services/hooks'
import type { AdminMenu } from '@/services/interfaces/admin.interface'

export const ADMIN_MENUS_QUERY_KEY = ['adminMenus'] as const
export const ADMIN_MENU_DETAIL_QUERY_KEY = ['adminMenu'] as const

type AdminMenusQueryOptions = Omit<UseQueryOptions<AdminMenu[], Error>, 'queryKey' | 'queryFn'>
type AdminMenuQueryOptions = Omit<UseQueryOptions<AdminMenu | null, Error>, 'queryKey' | 'queryFn'>

export function useAdminMenus(options?: AdminMenusQueryOptions) {
  const services = useServices()
  return useQuery<AdminMenu[], Error>({
    ...options,
    queryKey: ADMIN_MENUS_QUERY_KEY,
    queryFn: () => services.admin.navigation.listMenus(),
  })
}

export function useAdminMenu(name?: string | null, options?: AdminMenuQueryOptions) {
  const services = useServices()
  const enabled = Boolean(name) && (options?.enabled ?? true)
  return useQuery<AdminMenu | null, Error>({
    ...options,
    queryKey: [...ADMIN_MENU_DETAIL_QUERY_KEY, name ?? ''],
    enabled,
    queryFn: async () => {
      if (!name) return null
      return services.admin.navigation.getMenu(name)
    },
  })
}
