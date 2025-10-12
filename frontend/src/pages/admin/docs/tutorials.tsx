import { useAuth } from '@/lib/auth-context'
import { linkToOperation, linkToTag } from './_link'
import { ShieldAlert } from 'lucide-react'

export default function AdminDocsTutorials() {
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
      <h1 className="text-2xl font-semibold">Tutorials</h1>
      <section className="space-y-2">
        <h2 className="text-lg font-medium">Shelter onboarding</h2>
        <ol className="list-decimal ml-6 text-sm text-muted-foreground">
          <li>Create a shelter: <a className="underline" href={linkToOperation('createShelter')}>POST /shelters</a></li>
          <li>Add locations: <a className="underline" href={linkToOperation('createLocation')}>POST /locations</a></li>
          <li>Verify: <a className="underline" href={linkToOperation('listShelters')}>GET /shelters</a>, <a className="underline" href={linkToOperation('listLocations')}>GET /locations</a></li>
        </ol>
      </section>

      <section className="space-y-2">
        <h2 className="text-lg font-medium">Pet intake workflow</h2>
        <ol className="list-decimal ml-6 text-sm text-muted-foreground">
          <li>Create pet: <a className="underline" href={linkToOperation('createPet')}>POST /pets</a></li>
          <li>Record medical event: <a className="underline" href={linkToOperation('createMedicalRecord')}>POST /medical</a></li>
          <li>Link pet to owner: <a className="underline" href={linkToOperation('createPetOwner')}>POST /pet-owners</a></li>
          <li>Verify data: <a className="underline" href={linkToTag('Pets')}>Pets</a>, <a className="underline" href={linkToTag('Medical')}>Medical</a>, <a className="underline" href={linkToTag('PetOwners')}>PetOwners</a></li>
        </ol>
      </section>
    </div>
  )
}
