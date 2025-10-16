import { useEffect, useMemo, useState } from 'react'
import { assignUserRole, listRoles, revokeUserRole, searchUsers, type Role, type UserSummary } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@/components/ui/select'

export default function AdminUsersPage() {
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(false)
  const [users, setUsers] = useState<UserSummary[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [pageSize] = useState(20)
  const [roles, setRoles] = useState<Role[]>([])
  const [assign, setAssign] = useState<Record<string, string>>({}) // userId -> roleName

  useEffect(() => {
    async function init() {
      try {
        const r = await listRoles()
        setRoles(r)
      } catch {
        // ignore roles load error
      }
      await runSearch()
    }
    void init()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function runSearch() {
    setLoading(true)
    try {
      const res = await searchUsers(q || undefined, page, pageSize)
      setUsers(res.items)
      setTotal(res.total)
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to search users')
    } finally {
      setLoading(false)
    }
  }

  async function onAssign(userId: string) {
    const roleName = assign[userId]
    if (!roleName) return
    try {
      await assignUserRole(userId, roleName)
      // optimistic: update list
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, roles: Array.from(new Set([...u.roles, roleName])) } : u))
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to assign role')
    }
  }

  async function onRevoke(userId: string, roleName: string) {
    try {
      await revokeUserRole(userId, roleName)
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, roles: u.roles.filter(r => r !== roleName) } : u))
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to revoke role')
    }
  }

  const pageInfo = useMemo(() => ({ start: (page - 1) * pageSize + 1, end: Math.min(total, page * pageSize) }), [page, pageSize, total])

  return (
    <div className="p-4 space-y-4">
      <div>
        <h1 className="text-xl font-semibold">User Roles</h1>
        <p className="text-sm text-muted-foreground">Search users and assign or revoke roles.</p>
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
                <TableHead className="text-right">Assign</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {users.map(u => (
                <TableRow key={u.id}>
                  <TableCell>
                    <div className="font-medium">{u.name || '—'}</div>
                    <div className="text-xs text-muted-foreground">{u.email}</div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-wrap gap-1">
                      {u.roles.length ? u.roles.map(r => (
                        <span key={r} className="text-xs rounded border px-2 py-0.5">
                          {r} <button className="ml-1 text-destructive" onClick={() => onRevoke(u.id, r)}>×</button>
                        </span>
                      )) : <span className="text-xs text-muted-foreground">No roles</span>}
                    </div>
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
                      <Button size="sm" onClick={() => void onAssign(u.id)}>Assign</Button>
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
    </div>
  )
}
