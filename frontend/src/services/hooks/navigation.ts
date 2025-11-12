import { useQuery, type QueryClient, type UseQueryOptions } from '@tanstack/react-query'

import { useServices } from '@/services/hooks'
import type { NavigationMenu } from '@/services/interfaces/navigation.interface'

export const NAVIGATION_MENU_QUERY_KEY = ['navigationMenu'] as const

type NavigationMenuQueryOptions = Omit<UseQueryOptions<NavigationMenu | null, Error>, 'queryKey' | 'queryFn'>

export function useNavigationMenu(name?: string | null, options?: NavigationMenuQueryOptions) {
  const services = useServices()
  const enabled = Boolean(name) && (options?.enabled ?? true)
  const queryKey = [...NAVIGATION_MENU_QUERY_KEY, name ?? '']

  return useQuery<NavigationMenu | null, Error>({
    ...options,
    queryKey,
    enabled,
    queryFn: async () => {
      if (!name) return null
      return services.navigation.getMenu(name)
    },
  })
}

export function invalidateNavigationMenuQueries(queryClient: QueryClient, name?: string | null) {
  queryClient.invalidateQueries({ queryKey: NAVIGATION_MENU_QUERY_KEY })
  if (name) {
    queryClient.invalidateQueries({ queryKey: [...NAVIGATION_MENU_QUERY_KEY, name] })
  }
}

