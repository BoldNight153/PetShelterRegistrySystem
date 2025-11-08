import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'

import { useServices } from '@/services/hooks'
import type { Role, Permission } from '@/services/interfaces/role.interface'
import type { UserSummaryWithLock } from '@/services/interfaces/user.interface'
import type { SettingsMap, JsonValue } from '@/services/interfaces/types'

export function useRoles() {
  const services = useServices()
  return useQuery<Role[], Error>({ queryKey: ['roles'], queryFn: async () => (await services.roles?.listRoles?.()) ?? [] })
}

export function useUsers(q: string, page: number, pageSize: number) {
  const services = useServices()
  const key = ['users', q, page, pageSize] as const
  return useQuery<{ items: UserSummaryWithLock[]; total: number; page: number; pageSize: number }, Error>({ queryKey: key, queryFn: async () => (await services.users?.searchUsers(q || undefined, page, pageSize)) ?? { items: [], total: 0, page, pageSize } })
}

export function useAssignRole() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<unknown, Error, { userId: string; roleName: string }>({ mutationFn: (vars) => services.users!.assignUserRole(vars.userId, vars.roleName), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) })
}

export function useRevokeRole() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<unknown, Error, { userId: string; roleName: string }>({ mutationFn: (vars) => services.users!.revokeUserRole(vars.userId, vars.roleName), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) })
}

export function useLockUser() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<unknown, Error, { userId: string; reason: string; until?: string | null }>({ mutationFn: (vars) => services.users!.lockUser(vars.userId, vars.reason, vars.until ?? null), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) })
}

export function useUnlockUser() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<unknown, Error, { userId: string; note?: string }>({ mutationFn: (vars) => services.users!.unlockUser(vars.userId, vars.note), onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }) })
}

export function useUpsertRole() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<unknown, Error, { name: string; rank?: number; description?: string }>(
    {
      mutationFn: (vars) => services.roles!.upsertRole({ name: vars.name, rank: vars.rank ?? 0, description: vars.description }),
      onSuccess: () => qc.invalidateQueries({ queryKey: ['roles'] }),
    }
  )
}

export function useDeleteRole() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<unknown, Error, string>({ mutationFn: (name) => services.roles!.deleteRole(name), onSuccess: () => qc.invalidateQueries({ queryKey: ['roles'] }) })
}

export function usePermissions() {
  const services = useServices()
  return useQuery<Permission[], Error>({ queryKey: ['permissions'], queryFn: async () => (await services.roles?.listPermissions?.()) ?? [] })
}

export function useRolePermissions(roleName?: string) {
  const services = useServices()
  return useQuery<Permission[], Error>({ queryKey: ['rolePerms', roleName], enabled: !!roleName, queryFn: async () => (await services.roles?.listRolePermissions?.(roleName!)) ?? [] })
}

export function useGrantPermission() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<unknown, Error, { roleName: string; permission: string }>({
    mutationFn: ({ roleName, permission }) => services.roles!.grantPermission(roleName, permission),
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: ['rolePerms', vars.roleName] }),
  })
}

export function useRevokePermission() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<unknown, Error, { roleName: string; permission: string }>({
    mutationFn: ({ roleName, permission }) => services.roles!.revokePermission(roleName, permission),
    onSuccess: (_, vars) => qc.invalidateQueries({ queryKey: ['rolePerms', vars.roleName] }),
  })
}

export function useAdminSettings() {
  const services = useServices()
  return useQuery<SettingsMap, Error>({ queryKey: ['adminSettings'], queryFn: async () => (await services.admin?.settings?.loadSettings()) ?? {} })
}

export function useSaveAdminSettings() {
  const services = useServices()
  const qc = useQueryClient()
  return useMutation<unknown, Error, { category: string; entries: Array<{ key: string; value: JsonValue }> }>({
    mutationFn: ({ category, entries }) => services.admin!.settings.saveSettings(category, entries),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['adminSettings'] }),
  })
}
