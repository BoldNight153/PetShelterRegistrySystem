import { Link } from 'react-router-dom'
import { Shield, Users, KeyRound, BadgeCheck } from 'lucide-react'
import { useAuth } from '@/lib/auth-context'

const ADMIN_ROLES = new Set(['system_admin','admin','shelter_admin','staff_manager'])

export default function NavAdmin() {
  const { user } = useAuth()
  const roles = user?.roles || []
  const canSee = roles.some(r => ADMIN_ROLES.has(r))
  if (!canSee) return null
  return (
    <div className="px-2 py-1">
      <div className="text-xs uppercase text-muted-foreground px-2 pb-1">Admin</div>
      <ul className="space-y-1">
        <li>
          <Link className="flex items-center gap-2 rounded px-2 py-1 hover:bg-accent" to="/admin/roles">
            <BadgeCheck className="h-4 w-4" /> Roles
          </Link>
        </li>
        <li>
          <Link className="flex items-center gap-2 rounded px-2 py-1 hover:bg-accent" to="/admin/permissions">
            <KeyRound className="h-4 w-4" /> Permissions
          </Link>
        </li>
        <li>
          <Link className="flex items-center gap-2 rounded px-2 py-1 hover:bg-accent" to="/admin/users">
            <Users className="h-4 w-4" /> User Roles
          </Link>
        </li>
        <li>
          <Link className="flex items-center gap-2 rounded px-2 py-1 hover:bg-accent" to="/admin/audit">
            <Shield className="h-4 w-4" /> Audit Logs
          </Link>
        </li>
      </ul>
    </div>
  )
}
