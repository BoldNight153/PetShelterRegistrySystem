import { useQuery } from '@tanstack/react-query'

import { useServices } from '@/services/hooks'
import type { AdminAuthenticatorCatalogRecord } from '@/services/interfaces/admin.interface'
import { AUTHENTICATOR_CATALOG_QUERY_KEY } from '@/services/queryKeys'

export function useAuthenticatorCatalog(includeArchived = false) {
  const services = useServices()
  return useQuery<AdminAuthenticatorCatalogRecord[], Error>({
    queryKey: [AUTHENTICATOR_CATALOG_QUERY_KEY, 'admin', includeArchived],
    queryFn: async () => (await services.admin?.authenticators?.list({ includeArchived })) ?? [],
  })
}

export function useAuthenticators() {
  const { data: authenticators, ...rest } = useAuthenticatorCatalog(true)

  const authenticatorsById = new Map(authenticators?.map((authenticator) => [authenticator.id, authenticator]))

  const findAuthenticatorById = (id: string | null | undefined) => {
    if (!id) return undefined
    return authenticatorsById.get(id)
  }

  return { authenticators, findAuthenticatorById, ...rest }
}
