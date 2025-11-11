import { useMemo, useState } from 'react'
import { useRoles, useUsers, useAssignRole, useRevokeRole, useLockUser, useUnlockUser } from '@/services/hooks/admin'
import UserDetailsSheet from '@/components/admin/user-details-sheet'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@/components/ui/select'

export default function AdminUsersPage() {
  const [q, setQ] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize] = useState(20)
  const [assign, setAssign] = useState<Record<string, string>>({}) // userId -> roleName
  const { data: roles = [] } = useRoles()
  const usersQuery = useUsers(q, page, pageSize)
  const users = usersQuery.data?.items ?? []
  const total = usersQuery.data?.total ?? 0

  const loading = usersQuery.isLoading || usersQuery.isFetching || false

  async function runSearch() {
    await usersQuery.refetch()
  }

  const assignMutation = useAssignRole()
  async function onAssign(userId: string) {
    const roleName = assign[userId]
    if (!roleName) return
    try {
      await assignMutation.mutateAsync({ userId, roleName })
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to assign role')
    }
  }

  const revokeMutation = useRevokeRole()
  async function onRevoke(userId: string, roleName: string) {
    try {
      await revokeMutation.mutateAsync({ userId, roleName })
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to revoke role')
    }
  }

  const lockMutation = useLockUser()
  async function onLock(userId: string) {
    const reason = prompt('Lock reason (e.g., admin_action, security_suspicious):', 'admin_action') || 'admin_action'
    const until = prompt('Optional lock until (ISO timestamp), or leave blank for indefinite:', '')
    try {
      await lockMutation.mutateAsync({ userId, reason, until: until || null })
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to lock user')
    }
  }

  const unlockMutation = useUnlockUser()
  async function onUnlock(userId: string) {
    const unlockReason = prompt('Optional unlock note (will be saved with audit):', '') || undefined
    try {
      await unlockMutation.mutateAsync({ userId, note: unlockReason })
      alert('User unlocked. A password reset email has been sent to the user.')
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to unlock user')
    }
  }

  const pageInfo = useMemo(() => ({ start: (page - 1) * pageSize + 1, end: Math.min(total, page * pageSize) }), [page, pageSize, total])

  const [selectedUserId, setSelectedUserId] = useState<string | null>(null)
  const [sheetOpen, setSheetOpen] = useState(false)

  return (
    <div className="p-4 space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Users</h1>
        <p className="text-sm text-muted-foreground">Search users and manage accounts.</p>
      </div>

      <div className="flex flex-wrap items-end gap-2">
        <div className="flex-1 min-w-64">
          <label className="block text-xs mb-1">Search</label>
          <Input value={q} onChange={e => setQ(e.target.value)} placeholder="Name or email" />
        </div>
        <Button onClick={() => { setPage(1); void runSearch() }}>Search</Button>
      </div>

      {loading ? (
        <div className="text-sm">Loading…</div>
      ) : (
        <>
          <div className="text-xs text-muted-foreground">{total > 0 ? `${pageInfo.start}-${pageInfo.end} of ${total}` : 'No results'}</div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>User</TableHead>
                <TableHead>Roles</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Assign</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map(u => (
                <TableRow
                  key={u.id}
                  className="cursor-pointer"
                  onClick={(e) => {
                    const target = e.target as HTMLElement
                    // ignore clicks on interactive elements so they work as expected
                    if (target.closest('button, a, input, select, textarea')) return
                    setSelectedUserId(u.id)
                    setSheetOpen(true)
                  }}
                >
                  <TableCell>
                    <div className="font-medium">{u.name || '—'}</div>
                    <div className="text-xs text-muted-foreground">{u.email}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {u.roles.length ? u.roles.map(r => (
                        <span key={r} className="text-xs rounded border px-2 py-0.5">
                          {r} <button className="ml-1 text-destructive" onClick={(e) => { e.stopPropagation(); onRevoke(u.id, r) }}>×</button>
                        </span>
                      )) : <span className="text-xs text-muted-foreground">No roles</span>}
                    </div>
                  </TableCell>
                  <TableCell>
                    {u.lock ? (
                      <span className="text-xs rounded bg-yellow-100 dark:bg-yellow-900/40 border border-yellow-300 dark:border-yellow-800 px-2 py-0.5" title={u.lock.until || ''}>
                        Locked: {u.lock.reason}{u.lock.until ? ` until ${new Date(u.lock.until).toLocaleString()}` : ''}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">Active</span>
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      <Select value={assign[u.id] || ''} onValueChange={(v) => setAssign(prev => ({ ...prev, [u.id]: v }))}>
                        <SelectTrigger className="w-48"><SelectValue placeholder="Select role" /></SelectTrigger>
                        <SelectContent>
                          <SelectGroup>
                            <SelectLabel>Roles</SelectLabel>
                            {roles.sort((a,b)=> (b.rank ?? 0) - (a.rank ?? 0)).map(r => (
                              <SelectItem key={r.id} value={r.name}>{r.name}</SelectItem>
                            ))}
                          </SelectGroup>
                        </SelectContent>
                      </Select>
                      <Button size="sm" onClick={(e) => { e.stopPropagation(); void onAssign(u.id) }}>Assign</Button>
                      {u.lock ? (
                        <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); void onUnlock(u.id) }}>Unlock</Button>
                      ) : (
                        <Button size="sm" variant="outline" onClick={(e) => { e.stopPropagation(); void onLock(u.id) }}>Lock</Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          {total > pageSize && (
            <div className="flex items-center justify-between">
              <Button size="sm" variant="outline" disabled={page<=1} onClick={() => { setPage(p => Math.max(1, p-1)); void runSearch() }}>Prev</Button>
              <div className="text-xs">Page {page}</div>
              <Button size="sm" variant="outline" disabled={page*pageSize>=total} onClick={() => { setPage(p => p+1); void runSearch() }}>Next</Button>
            </div>
          )}
        </>
      )}
      <UserDetailsSheet userId={selectedUserId} open={sheetOpen} onOpenChange={(v) => { setSheetOpen(v); if (!v) setSelectedUserId(null) }} />
    </div>
  )
}
