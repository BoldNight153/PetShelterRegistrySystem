import { useAuth } from '@/lib/auth-context'
import { linkToOperation, linkToTag } from './_link'
import { ShieldAlert } from 'lucide-react'

export default function AdminDocsIntroduction() {
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
      <div>
        <h1 className="text-2xl font-semibold">Introduction</h1>
        <p className="text-muted-foreground mt-1">Welcome to the Pet Shelter Registry System Admin Documentation.</p>
      </div>

      <section className="space-y-2">
        <h2 className="text-lg font-medium">What’s in the API</h2>
        <p className="text-sm text-muted-foreground">
          The API covers core resources: Pets, Shelters, Locations, Owners, Medical records, Events, and Pet-Owner links.
          Browse by tag in ReDoc:
        </p>
        <ul className="list-disc ml-6 text-sm">
          <li><a className="underline" href={linkToTag('Pets')}>Pets</a> — list, create, update, delete</li>
          <li><a className="underline" href={linkToTag('Shelters')}>Shelters</a> — manage shelters</li>
          <li><a className="underline" href={linkToTag('Locations')}>Locations</a> — per-shelter locations/kennels</li>
          <li><a className="underline" href={linkToTag('Owners')}>Owners</a> — manage people/contacts</li>
          <li><a className="underline" href={linkToTag('Medical')}>Medical</a> — record medical events</li>
          <li><a className="underline" href={linkToTag('Events')}>Events</a> — system events</li>
          <li><a className="underline" href={linkToTag('PetOwners')}>PetOwners</a> — pet ↔ owner relationships</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-lg font-medium">Quick links to common operations</h2>
        <ul className="list-disc ml-6 text-sm">
          <li><a className="underline" href={linkToOperation('listPets')}>List pets</a>, <a className="underline" href={linkToOperation('createPet')}>Create pet</a>, <a className="underline" href={linkToOperation('getPet')}>Get pet</a></li>
          <li><a className="underline" href={linkToOperation('listShelters')}>List shelters</a>, <a className="underline" href={linkToOperation('createShelter')}>Create shelter</a></li>
          <li><a className="underline" href={linkToOperation('listLocations')}>List locations</a>, <a className="underline" href={linkToOperation('createLocation')}>Create location</a></li>
          <li><a className="underline" href={linkToOperation('listOwners')}>List owners</a>, <a className="underline" href={linkToOperation('createOwner')}>Create owner</a></li>
          <li><a className="underline" href={linkToOperation('listMedicalRecords')}>List medical records</a>, <a className="underline" href={linkToOperation('createMedicalRecord')}>Create medical record</a></li>
        </ul>
      </section>
    </div>
  )
}
