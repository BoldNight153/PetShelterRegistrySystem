import { useAuth } from '@/lib/auth-context'
import { linkToOperation, linkToTag } from './_link'
import { ShieldAlert } from 'lucide-react'

export default function AdminDocsGetStarted() {
  const { user } = useAuth()
  const canSeeAdmin = !!user?.roles?.includes('system_admin')
  if (!canSeeAdmin) {
    return (
      <div className="p-6">
        <div className="flex items-center gap-2 text-red-600 dark:text-red-400"><ShieldAlert className="h-5 w-5" /> Access denied</div>
        <p className="text-sm text-muted-foreground mt-2">Please sign in to view documentation.</p>
      </div>
    )
  }
  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-semibold">Get Started</h1>
      <ol className="list-decimal ml-6 space-y-2 text-sm text-muted-foreground">
        <li>Sign in with a system administrator account.</li>
        <li>Review Admin → Roles/Permissions and assign roles as needed.</li>
        <li>Open the <a className="underline" href="/docs">API reference</a> and skim the <a className="underline" href={linkToTag('Pets')}>Pets</a> and <a className="underline" href={linkToTag('Shelters')}>Shelters</a> sections.</li>
        <li>Create a shelter, then a location, then a pet:
          <ul className="list-disc ml-6 mt-2">
            <li><a className="underline" href={linkToOperation('createShelter')}>POST /shelters</a></li>
            <li><a className="underline" href={linkToOperation('createLocation')}>POST /locations</a></li>
            <li><a className="underline" href={linkToOperation('createPet')}>POST /pets</a></li>
          </ul>
        </li>
        <li>Fetch your data to verify:
          <ul className="list-disc ml-6 mt-2">
            <li><a className="underline" href={linkToOperation('listShelters')}>GET /shelters</a></li>
            <li><a className="underline" href={linkToOperation('listLocations')}>GET /locations</a></li>
            <li><a className="underline" href={linkToOperation('listPets')}>GET /pets</a></li>
          </ul>
        </li>
      </ol>
    </div>
  )
}
