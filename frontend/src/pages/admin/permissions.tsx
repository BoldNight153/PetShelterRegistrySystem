import { useCallback, useEffect, useMemo, useState } from 'react'
import { useServices } from '@/services/hooks'
import { type Permission, type Role } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@/components/ui/select'

export default function AdminPermissionsPage() {
  const [permissions, setPermissions] = useState<Permission[]>([])
  const [roles, setRoles] = useState<Role[]>([])
  const [selectedRole, setSelectedRole] = useState<string>('')
  const [rolePerms, setRolePerms] = useState<Record<string, boolean>>({})
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const services = useServices()

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      // listPermissions is exposed by the roles service implementation
      const [perms, r] = await Promise.all([services.roles?.listPermissions?.() ?? [], services.roles?.listRoles?.() ?? []])
      setPermissions(perms)
      setRoles(r)
      if (!selectedRole && r.length) setSelectedRole(r[0].name)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load')
    } finally {
      setLoading(false)
    }
  }, [selectedRole, services.roles])

  useEffect(() => { void load() }, [load])

  useEffect(() => {
    async function loadRolePerms(name: string) {
      if (!name) return
      try {
        const rp = await services.roles?.listRolePermissions?.(name) ?? []
        const map: Record<string, boolean> = {}
        for (const p of rp) map[p.name] = true
        setRolePerms(map)
      } catch {
        // ignore errors on role perms load
      }
    }
    if (selectedRole) loadRolePerms(selectedRole)
  }, [selectedRole, services.roles])

  const filtered = useMemo(() => (
    permissions.filter(p => !q || p.name.toLowerCase().includes(q.toLowerCase()))
  ), [permissions, q])

  async function onToggle(p: string, enabled: boolean) {
    try {
      if (!selectedRole) return
      if (enabled) await services.roles?.grantPermission?.(selectedRole, p)
      else await services.roles?.revokePermission?.(selectedRole, p)
      setRolePerms(prev => ({ ...prev, [p]: enabled }))
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

      {error && <div className="text-sm text-destructive">{error}</div>}
      {loading ? (
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
