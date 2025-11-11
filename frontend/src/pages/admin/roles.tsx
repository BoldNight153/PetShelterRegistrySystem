import { useState } from 'react'
import { useRoles, useUpsertRole, useDeleteRole } from '@/services/hooks/admin'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

export default function AdminRolesPage() {
  const [form, setForm] = useState<{ name: string; rank: number; description: string }>({ name: '', rank: 0, description: '' })

  const { data: roles = [], isLoading, isError, error } = useRoles()
  const upsert = useUpsertRole()
  const del = useDeleteRole()

  async function onUpsert(e: React.FormEvent) {
    e.preventDefault()
    if (!form.name.trim()) return
    try {
      await upsert.mutateAsync({ name: form.name.trim(), rank: Number(form.rank) || 0, description: form.description || undefined })
      setForm({ name: '', rank: 0, description: '' })
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to save role')
    }
  }

  async function onDelete(name: string) {
    if (!confirm(`Delete role "${name}"?`)) return
    try {
      await del.mutateAsync(name)
    } catch (e: unknown) {
      alert(e instanceof Error ? e.message : 'Failed to delete role')
    }
  }

  return (
    <div className="p-4 space-y-4">
      <div>
        <h1 className="text-xl font-semibold">Roles</h1>
        <p className="text-sm text-muted-foreground">Create, update, and delete roles. Higher rank implies higher privilege in UI sorting.</p>
      </div>

      <form onSubmit={onUpsert} className="flex flex-wrap items-end gap-2">
        <div className="flex-1 min-w-48">
          <label className="block text-xs mb-1">Name</label>
          <Input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="e.g. shelter_admin" />
        </div>
        <div className="w-32">
          <label className="block text-xs mb-1">Rank</label>
          <Input type="number" value={form.rank} onChange={e => setForm({ ...form, rank: Number(e.target.value) })} />
        </div>
        <div className="flex-1 min-w-64">
          <label className="block text-xs mb-1">Description</label>
          <Input value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="optional" />
        </div>
        <Button type="submit">Save</Button>
      </form>

      {isError && <div className="text-destructive text-sm">{error?.message ?? 'Failed to load roles'}</div>}
      {isLoading ? (
        <div className="text-sm">Loading…</div>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Rank</TableHead>
              <TableHead>Description</TableHead>
              <TableHead></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {roles.sort((a, b) => (b.rank ?? 0) - (a.rank ?? 0)).map(r => (
              <TableRow key={r.id}>
                <TableCell className="font-mono">{r.name}</TableCell>
                <TableCell>{r.rank}</TableCell>
                <TableCell className="max-w-[40ch] truncate" title={r.description || ''}>{r.description || '—'}</TableCell>
                <TableCell className="text-right">
                  <Button variant="destructive" size="sm" onClick={() => onDelete(r.name)}>Delete</Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  )
}
