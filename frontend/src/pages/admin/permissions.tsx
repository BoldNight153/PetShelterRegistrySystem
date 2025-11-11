import { useMemo, useState } from 'react'
import { usePermissions, useRoles, useRolePermissions, useGrantPermission, useRevokePermission } from '@/services/hooks/admin'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@/components/ui/select'

export default function AdminPermissionsPage() {
  const [selectedRole, setSelectedRole] = useState<string>('')
  const [q, setQ] = useState('')

  const { data: permissions = [], isLoading: permsLoading, isError: permsError, error: permsErrorObj } = usePermissions()
  const { data: roles = [] } = useRoles()
  const { data: rolePermsList = [], isLoading: rolePermsLoading } = useRolePermissions(selectedRole)

  const grant = useGrantPermission()
  const revoke = useRevokePermission()

  const rolePerms: Record<string, boolean> = useMemo(() => {
    const map: Record<string, boolean> = {}
    for (const p of rolePermsList ?? []) map[p.name] = true
    return map
  }, [rolePermsList])

  const filtered = useMemo(() => (
    permissions.filter(p => !q || p.name.toLowerCase().includes(q.toLowerCase()))
  ), [permissions, q])

  async function onToggle(p: string, enabled: boolean) {
    try {
      if (!selectedRole) return
      if (enabled) await grant.mutateAsync({ roleName: selectedRole, permission: p })
      else await revoke.mutateAsync({ roleName: selectedRole, permission: p })
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to update')
    }
  }

  return (
    <div className="p-4 space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Permissions</h1>
        <p className="text-sm text-muted-foreground">Grant or revoke permissions for a selected role.</p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="w-64">
          <label className="block text-xs mb-1">Role</label>
          <Select value={selectedRole} onValueChange={setSelectedRole}>
            <SelectTrigger className="w-full"><SelectValue placeholder="Select role" /></SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectLabel>Roles</SelectLabel>
                {roles.sort((a,b)=> (b.rank ?? 0) - (a.rank ?? 0)).map(r => (
                  <SelectItem key={r.id} value={r.name}>{r.name}</SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>
        <div className="flex-1 min-w-64">
          <label className="block text-xs mb-1">Filter</label>
          <Input value={q} onChange={e => setQ(e.target.value)} placeholder="Search permission by name" />
        </div>
      </div>

      {permsError && <div className="text-sm text-destructive">{permsErrorObj?.message ?? 'Failed to load'}</div>}
      {permsLoading || rolePermsLoading ? (
        <div className="text-sm">Loading…</div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Permission</TableHead>
              <TableHead>Description</TableHead>
              <TableHead className="text-right">Granted</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map(p => (
              <TableRow key={p.id}>
                <TableCell className="font-mono">{p.name}</TableCell>
                <TableCell className="max-w-[60ch] truncate" title={p.description || ''}>{p.description || '—'}</TableCell>
                <TableCell className="text-right">
                  {rolePerms[p.name] ? (
                    <Button size="sm" variant="destructive" onClick={() => onToggle(p.name, false)}>Revoke</Button>
                  ) : (
                    <Button size="sm" onClick={() => onToggle(p.name, true)}>Grant</Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}
