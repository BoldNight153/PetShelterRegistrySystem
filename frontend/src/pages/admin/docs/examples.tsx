import { useAuth } from '@/lib/auth-context'
import { ShieldAlert } from 'lucide-react'
import * as React from 'react'
import { linkToOperation, linkToTag } from './_link'

export default function AdminDocsExamples() {
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
    <div className="p-6 space-y-8">
      <h1 className="text-2xl font-semibold">API Examples</h1>

      <section className="space-y-3">
        <h2 className="text-lg font-medium">Authentication</h2>
        <p className="text-sm text-muted-foreground">Quick cURL flows for CSRF, register, login, refresh, and logout.</p>
        <div className="grid md:grid-cols-2 gap-4">
          <ExampleCard title="Get CSRF token">
            <pre className="text-xs overflow-auto"><code>{`curl -s http://localhost:4000/auth/csrf | jq`}</code></pre>
          </ExampleCard>
          <ExampleCard title="Register user">
            <pre className="text-xs overflow-auto"><code>{`curl -X POST http://localhost:4000/auth/register -H 'Content-Type: application/json' -H "x-csrf-token: $(curl -s http://localhost:4000/auth/csrf | jq -r .csrfToken)" --cookie "csrfToken=$(curl -s http://localhost:4000/auth/csrf | jq -r .csrfToken)" -d '{"name":"Admin","email":"admin@example.com","password":"Admin123!@#"}'`}</code></pre>
          </ExampleCard>
          <ExampleCard title="Login (sets cookies)">
            <pre className="text-xs overflow-auto"><code>{`curl -i -X POST http://localhost:4000/auth/login -H 'Content-Type: application/json' -H "x-csrf-token: $CSRF" --cookie "csrfToken=$CSRF" -d '{"email":"admin@example.com","password":"Admin123!@#"}'`}</code></pre>
          </ExampleCard>
          <ExampleCard title="Refresh (rotate refresh token)">
            <pre className="text-xs overflow-auto"><code>{`curl -i -X POST http://localhost:4000/auth/refresh -H "x-csrf-token: $CSRF" --cookie "csrfToken=$CSRF; refreshToken=<from login>"`}</code></pre>
          </ExampleCard>
        </div>
        <p className="text-xs text-muted-foreground">See diagnostics at <a className="underline" href="/auth/mode">/auth/mode</a>.</p>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-medium">CRUD workflow</h2>
        <p className="text-sm text-muted-foreground">Create a shelter → location → pet, then list them. Deep link to the spec for details.</p>
        <ul className="list-disc ml-6 text-sm">
          <li><a className="underline" href={linkToOperation('createShelter')}>Create shelter</a>, then <a className="underline" href={linkToOperation('listShelters')}>List shelters</a></li>
          <li><a className="underline" href={linkToOperation('createLocation')}>Create location</a>, then <a className="underline" href={linkToOperation('listLocations')}>List locations</a></li>
          <li><a className="underline" href={linkToOperation('createPet')}>Create pet</a>, then <a className="underline" href={linkToOperation('listPets')}>List pets</a></li>
        </ul>
        <div className="grid md:grid-cols-2 gap-4">
          <ExampleCard title="Create shelter (curl)">
            <pre className="text-xs overflow-auto"><code>{`curl -X POST http://localhost:4000/shelters -H 'Content-Type: application/json' -d '{"name":"Central Shelter"}' | jq`}</code></pre>
          </ExampleCard>
          <ExampleCard title="Create location (curl)">
            <pre className="text-xs overflow-auto"><code>{`curl -X POST http://localhost:4000/locations -H 'Content-Type: application/json' -d '{"shelterId":"central-shelter","code":"A-1"}' | jq`}</code></pre>
          </ExampleCard>
          <ExampleCard title="Create pet (curl)">
            <pre className="text-xs overflow-auto"><code>{`curl -X POST http://localhost:4000/pets -H 'Content-Type: application/json' -d '{"name":"Milo","species":"Dog"}' | jq`}</code></pre>
          </ExampleCard>
          <ExampleCard title="List pets (curl)">
            <pre className="text-xs overflow-auto"><code>{`curl -s http://localhost:4000/pets | jq`}</code></pre>
          </ExampleCard>
        </div>
      </section>

      <section className="space-y-3">
        <h2 className="text-lg font-medium">Explore by tag</h2>
        <p className="text-sm text-muted-foreground">Jump directly to resource groups in the reference:</p>
        <ul className="list-disc ml-6 text-sm">
          <li><a className="underline" href={linkToTag('Pets')}>Pets</a></li>
          <li><a className="underline" href={linkToTag('Shelters')}>Shelters</a></li>
          <li><a className="underline" href={linkToTag('Locations')}>Locations</a></li>
          <li><a className="underline" href={linkToTag('Owners')}>Owners</a></li>
          <li><a className="underline" href={linkToTag('Medical')}>Medical</a></li>
          <li><a className="underline" href={linkToTag('Events')}>Events</a></li>
          <li><a className="underline" href={linkToTag('PetOwners')}>PetOwners</a></li>
        </ul>
      </section>
    </div>
  )
}

function ExampleCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border bg-card text-card-foreground p-3">
      <div className="text-sm font-medium mb-2">{title}</div>
      {children}
    </div>
  )
}
