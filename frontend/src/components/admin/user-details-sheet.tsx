import { useEffect, useState } from 'react'
import { Button } from '@/components/ui/button'
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription, SheetFooter } from '@/components/ui/sheet'
import { useServices } from '@/services/hooks'
import type { UserDetail, Role } from '@/lib/api'
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@/components/ui/select'

type Props = {
  userId: string | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

export default function UserDetailsSheet({ userId, open, onOpenChange }: Props) {
  const [user, setUser] = useState<UserDetail | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [reloadIndex, setReloadIndex] = useState(0)
  const [rolesToAssign, setRolesToAssign] = useState<Record<string,string>>({})
  const [availableRoles, setAvailableRoles] = useState<Role[]>([])
  const [rolePermissions, setRolePermissions] = useState<Record<string, { id: string; name: string }[]>>({})
  const [sessions, setSessions] = useState<Array<{ id: string; createdAt?: string; ip?: string; userAgent?: string }>>([])
  const [sessionsAvailable, setSessionsAvailable] = useState<boolean | null>(null)
  const services = useServices()
  const usersService = services.users
  const rolesService = services.roles

  useEffect(() => {
    if (!open) {
      // clear state when closed
      setUser(null)
      setError(null)
      setAvailableRoles([])
      setRolePermissions({})
      setSessions([])
      setSessionsAvailable(null)
      return
    }
    if (!userId) return
    let mounted = true
    async function load() {
      setLoading(true)
      setError(null)
      try {
  const u = await usersService?.getUser(String(userId)) ?? null
        if (!mounted) return
        setUser(u)

        // use shared API helper to load roles
  const r = await rolesService?.listRoles?.() ?? []
        if (!mounted) return
        setAvailableRoles(r)

        // load permissions for each role the user has (if any)
        if (u && (u.roles || []).length > 0) {
          const permsMap: Record<string, { id: string; name: string }[]> = {}
          await Promise.all((u.roles || []).map(async (roleName) => {
            try {
              const p = await rolesService?.listRolePermissions?.(roleName) ?? []
              if (!mounted) return
              permsMap[roleName] = p as { id: string; name: string }[]
            } catch {
              // ignore per-role permission load failures
              permsMap[roleName] = []
            }
          }))
          if (mounted) setRolePermissions(permsMap)
        } else {
          if (mounted) setRolePermissions({})
        }

        // try loading sessions - prefer typed service method, fallback to legacy fetch path
        try {
          if (usersService?.listSessions) {
            try {
              const ss = await usersService.listSessions(String(userId))
              if (mounted) {
                setSessionsAvailable(true)
                setSessions(Array.isArray(ss) ? ss : [])
              }
            } catch (e: unknown) {
              let status: number | undefined
              if (typeof e === 'object' && e !== null && 'status' in e) {
                status = (e as { status?: number }).status
              }
              if (status === 404) {
                if (mounted) setSessionsAvailable(false)
              } else {
                if (mounted) setSessionsAvailable(false)
              }
            }
          } else {
            // Use the legacy fetch path for sessions (keeps compatibility across servers).
            const sres = await fetch(`/admin/users/${encodeURIComponent(String(userId))}/sessions`, { credentials: 'include' })
            if (sres.status === 404) {
              if (mounted) setSessionsAvailable(false)
            } else if (sres.ok) {
              const ss = await sres.json()
              if (mounted) {
                setSessionsAvailable(true)
                setSessions(Array.isArray(ss) ? ss : [])
              }
            } else {
              if (mounted) setSessionsAvailable(false)
            }
          }
        } catch {
          if (mounted) setSessionsAvailable(false)
        }
      } catch (err) {
  // surface error to UI so user can retry and log for debugging
  console.error('Failed to load user details', err)
        if (mounted) setError(err instanceof Error ? err.message : String(err || 'Failed to load user'))
      } finally {
        if (mounted) setLoading(false)
      }
    }
    void load()
    return () => { mounted = false }
  }, [open, userId, reloadIndex, usersService, rolesService])

  async function handleLock() {
    if (!user) return
    const reason = prompt('Lock reason', 'admin_action') || 'admin_action'
    const until = prompt('Optional lock until (ISO), or blank for indefinite', '') || null
  await usersService?.lockUser?.(user.id, reason, until)
    setUser(prev => prev ? { ...prev, lock: { reason, until } } : prev)
  }

  async function handleUnlock() {
    if (!user) return
  await usersService?.unlockUser?.(user.id)
    setUser(prev => prev ? { ...prev, lock: null } : prev)
  }

  async function handleAssign(roleName: string) {
    if (!user) return
  await usersService?.assignUserRole?.(user.id, roleName)
    setUser(prev => prev ? { ...prev, roles: Array.from(new Set([...(prev.roles||[]), roleName])) } : prev)
  }

  async function handleRevoke(roleName: string) {
    if (!user) return
  await usersService?.revokeUserRole?.(user.id, roleName)
    setUser(prev => prev ? { ...prev, roles: (prev.roles||[]).filter(r => r!==roleName) } : prev)
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right">
        <SheetHeader>
          <SheetTitle>{user ? (user.name || user.email) : 'User details'}</SheetTitle>
          <SheetDescription>
            {user ? `ID: ${user.id}` : (loading ? 'Loading...' : (error ? `Error: ${error}` : 'No user selected'))}
            {error && (
              <div className="mt-2 flex gap-2">
                <Button size="sm" onClick={() => setReloadIndex(v => v + 1)}>Retry</Button>
              </div>
            )}
          </SheetDescription>
        </SheetHeader>

        <div className="p-4 space-y-4">
            {loading && <div>Loading…</div>}
            {!loading && error && (
              <div className="text-sm text-destructive">Error loading user: {error}</div>
            )}
          {user && (
            <div className="space-y-3">
              <div className="text-sm text-muted-foreground">Email</div>
              <div className="font-medium">{user.email}</div>

              <div className="text-sm text-muted-foreground">Status</div>
              <div>
                {user.lock ? (
                  <div className="text-xs rounded bg-yellow-100 dark:bg-yellow-900/40 border border-yellow-300 dark:border-yellow-800 px-2 py-0.5">Locked: {user.lock.reason}{user.lock.until ? ` until ${new Date(user.lock.until).toLocaleString()}` : ''}</div>
                ) : (
                  <div className="text-xs text-muted-foreground">Active</div>
                )}
              </div>

              <div>
                <div className="text-sm text-muted-foreground">Timestamps</div>
                <div className="text-xs text-muted-foreground">Created: {user.createdAt ? new Date(user.createdAt).toLocaleString() : '—'}</div>
                <div className="text-xs text-muted-foreground">Last login: {user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : '—'}</div>
              </div>

              <div>
                <div className="text-sm text-muted-foreground">Roles</div>
                <div className="flex flex-wrap gap-2">
                  {(user.roles||[]).map(r => (
                    <div key={r} className="rounded border px-2 py-1 text-xs flex items-center gap-2">
                      <span>{r}</span>
                      <button className="text-destructive" onClick={(e) => { e.stopPropagation(); void handleRevoke(r) }}>Revoke</button>
                    </div>
                  ))}
                </div>
                {Object.keys(rolePermissions).length > 0 && (
                  <div className="mt-2">
                    <div className="text-sm text-muted-foreground">Permissions (by role)</div>
                    <div className="space-y-2">
                      {Object.entries(rolePermissions).map(([roleName, perms]) => (
                        <div key={roleName}>
                          <div className="text-xs font-medium">{roleName}</div>
                          <div className="text-xs text-muted-foreground">{perms.map(p => p.name).join(', ') || '—'}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="mt-2 flex items-center gap-2">
                  <Select onValueChange={(v) => setRolesToAssign(prev => ({ ...prev, [user.id]: v }))}>
                    <SelectTrigger className="w-48"><SelectValue placeholder="Assign role" /></SelectTrigger>
                    <SelectContent>
                      <SelectGroup>
                        <SelectLabel>Roles</SelectLabel>
                        {availableRoles.map(r => <SelectItem key={r.id} value={r.name}>{r.name}</SelectItem>)}
                      </SelectGroup>
                    </SelectContent>
                  </Select>
                  <Button onClick={() => { const role = rolesToAssign[user.id]; if (role) void handleAssign(role) }} size="sm">Assign</Button>
                </div>
              </div>

              <div>
                <div className="text-sm text-muted-foreground">Metadata</div>
                <pre className="text-xs bg-surface p-2 rounded overflow-auto">{JSON.stringify(user.metadata ?? {}, null, 2)}</pre>
              </div>

              <div>
                <div className="text-sm text-muted-foreground">Sessions</div>
                {sessionsAvailable === null && (<div className="text-xs text-muted-foreground">Checking sessions availability…</div>)}
                {sessionsAvailable === false && (<div className="text-xs text-muted-foreground">Session listing not available on this server.</div>)}
                {sessionsAvailable === true && (
                  <div className="space-y-2">
                    {sessions.length === 0 && <div className="text-xs text-muted-foreground">No active sessions.</div>}
                    {sessions.map(s => (
                      <div key={s.id} className="flex items-center justify-between text-xs border rounded p-2">
                        <div>
                          <div className="font-medium">{s.id}</div>
                          <div className="text-muted-foreground">{s.ip ?? 'IP unknown'} • {s.userAgent ?? 'UA unknown'}</div>
                        </div>
                        <div className="text-xs text-muted-foreground">{s.createdAt ? new Date(s.createdAt).toLocaleString() : ''}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        <SheetFooter>
          <div className="flex gap-2">
            {user && (user.lock ? (
              <Button variant="outline" onClick={() => void handleUnlock()}>Unlock</Button>
            ) : (
              <Button variant="destructive" onClick={() => void handleLock()}>Lock</Button>
            ))}
            <Button onClick={() => onOpenChange(false)}>Close</Button>
          </div>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}
