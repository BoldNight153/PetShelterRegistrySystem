import { OwnerRole, PetStatus, PrismaClient, Sex } from '@prisma/client'
import argon2 from 'argon2'
import { DEFAULT_AUDIT_SETTINGS } from '../src/types/auditSettings'

// Declare minimal process type to appease TS in environments without @types/node
declare const process: { env: Record<string, string | undefined> }
const prisma: any = new PrismaClient()

const daysAgo = (days: number) => {
  const date = new Date()
  date.setDate(date.getDate() - days)
  return date
}

type ShelterSeed = {
  id: string
  name: string
  address: Record<string, any>
  phone?: string
  email?: string
  capacity?: number
  notes?: string
  locations: Array<{
    id: string
    code: string
    description?: string
    capacity?: number
    notes?: string
  }>
}

type OwnerSeed = {
  email: string
  firstName: string
  lastName: string
  phone?: string
  type?: string
  address?: Record<string, any>
  notes?: string
}

type PetSeed = {
  microchip: string
  name: string
  species: string
  breed?: string
  sex: Sex
  status: PetStatus
  color?: string
  weightKg?: number
  sterilized?: boolean
  intakeAt?: Date
  intakeAtDaysAgo?: number
  shelterRef?: string | null
  locationRef?: string | null
  notes?: string
  owners: Array<{
    email: string
    role: OwnerRole
    isPrimary?: boolean
    startDate?: Date
    startDaysAgo?: number
    endDate?: Date | null
    endDaysAgo?: number
    notes?: string
  }>
  medicalRecords?: Array<{
    visitOffsetDays: number
    vetName?: string
    recordType?: string
    notes?: string
  }>
  events?: Array<{
    type: string
    offsetDays: number
    notes?: string
    fromShelterRef?: string | null
    toShelterRef?: string | null
  }>
}

type DemoUserSeed = {
  email: string
  name: string
  roles: string[]
  metadata?: Record<string, any>
}

const shelterSeeds: ShelterSeed[] = [
  {
    id: 'central-shelter',
    name: 'Central Shelter',
    address: { line1: '120 Paw Ave', city: 'Metropolis', state: 'NY', zip: '10001' },
    phone: '555-0100',
    email: 'central@shelter.local',
    capacity: 120,
    notes: 'Flagship intake center and medical hub.',
    locations: [
      { id: 'central-a1', code: 'A-1', description: 'Front row kennels for quick intake', capacity: 12 },
      { id: 'central-med', code: 'MED-1', description: 'Medical isolation ward', capacity: 6 },
      { id: 'central-rehab', code: 'REHAB', description: 'Behavior & training suites', capacity: 8 },
    ],
  },
  {
    id: 'north-shelter',
    name: 'North Shelter',
    address: { line1: '45 Tundra Rd', city: 'Northgate', state: 'WA', zip: '98101' },
    phone: '555-0200',
    email: 'north@shelter.local',
    capacity: 80,
    notes: 'Handles northern community outreach and transfers.',
    locations: [
      { id: 'north-a1', code: 'N-A1', description: 'General population pods', capacity: 10 },
      { id: 'north-foster', code: 'N-FOSTER', description: 'Foster pickup staging' },
    ],
  },
  {
    id: 'west-shelter',
    name: 'West Shelter',
    address: { line1: '908 Sunset Blvd', city: 'Sundale', state: 'CA', zip: '94105' },
    phone: '555-0300',
    email: 'west@shelter.local',
    capacity: 60,
    notes: 'Focuses on small animals and pocket pets.',
    locations: [
      { id: 'west-a1', code: 'W-A1', description: 'Small animal room', capacity: 16 },
      { id: 'west-training', code: 'W-TRN', description: 'Training & agility yard' },
    ],
  },
]

const ownerSeeds: OwnerSeed[] = [
  { email: 'alice.moreno@example.com', firstName: 'Alice', lastName: 'Moreno', phone: '555-1111', type: 'individual', address: { city: 'Metropolis', state: 'NY', zip: '10003' } },
  { email: 'bob.jones@example.com', firstName: 'Bob', lastName: 'Jones', phone: '555-2222', type: 'individual', address: { city: 'Northgate', state: 'WA', zip: '98105' } },
  { email: 'carla.singh@example.com', firstName: 'Carla', lastName: 'Singh', phone: '555-3333', type: 'individual', address: { city: 'Sundale', state: 'CA', zip: '94107' } },
  { email: 'david.chen@example.com', firstName: 'David', lastName: 'Chen', phone: '555-4444', type: 'individual', address: { city: 'Metropolis', state: 'NY', zip: '10004' } },
  { email: 'emily.foster@example.com', firstName: 'Emily', lastName: 'Foster', phone: '555-5555', type: 'individual', address: { city: 'Northgate', state: 'WA', zip: '98103' } },
  { email: 'greg.ramirez@example.com', firstName: 'Greg', lastName: 'Ramirez', phone: '555-6666', type: 'individual', address: { city: 'Sundale', state: 'CA', zip: '94105' } },
  { email: 'holly.park@example.com', firstName: 'Holly', lastName: 'Park', phone: '555-7777', type: 'individual', address: { city: 'Metropolis', state: 'NY', zip: '10005' } },
  { email: 'ivy.ngo@example.com', firstName: 'Ivy', lastName: 'Ngo', phone: '555-8888', type: 'individual', address: { city: 'Northgate', state: 'WA', zip: '98109' } },
  { email: 'jordan.carey@example.com', firstName: 'Jordan', lastName: 'Carey', phone: '555-9999', type: 'individual', address: { city: 'Sundale', state: 'CA', zip: '94110' } },
  { email: 'sarah.lake@example.com', firstName: 'Sarah', lastName: 'Lake', phone: '555-1212', type: 'individual', address: { city: 'Metropolis', state: 'NY', zip: '10002' } },
  { email: 'maria.adopter@example.com', firstName: 'Maria', lastName: 'Adopter', phone: '555-1313', type: 'individual', address: { city: 'Sundale', state: 'CA', zip: '94112' } },
  { email: 'noah.reed@example.com', firstName: 'Noah', lastName: 'Reed', phone: '555-1414', type: 'individual', address: { city: 'Northgate', state: 'WA', zip: '98107' } },
  { email: 'liam.turner@example.com', firstName: 'Liam', lastName: 'Turner', phone: '555-1515', type: 'individual', address: { city: 'Metropolis', state: 'NY', zip: '10006' } },
  { email: 'pawsitive.rescue@example.com', firstName: 'Pawsitive', lastName: 'Partners', phone: '555-9090', type: 'organization', address: { city: 'Metropolis', state: 'NY', zip: '10001' }, notes: 'Partner rescue organization' },
]

const petSeeds: PetSeed[] = [
  {
    microchip: 'DOG-0001',
    name: 'Milo',
    species: 'Dog',
    breed: 'Beagle',
    sex: Sex.MALE,
    status: PetStatus.FOSTERED,
    color: 'Tri-color',
    weightKg: 11.2,
    sterilized: true,
    intakeAtDaysAgo: 45,
    shelterRef: 'central-shelter',
    locationRef: 'central-a1',
    notes: 'Owner surrender after relocation.',
    owners: [
      { email: 'sarah.lake@example.com', role: OwnerRole.FOSTER, isPrimary: true, startDaysAgo: 20, notes: 'Experienced beagle foster' },
      { email: 'maria.adopter@example.com', role: OwnerRole.OWNER, isPrimary: false, startDaysAgo: 5, notes: 'Adoption paperwork pending' },
    ],
    medicalRecords: [
      { visitOffsetDays: 40, vetName: 'Dr. Priya Vet', recordType: 'wellness_exam', notes: 'Healthy; anxious around loud noises' },
      { visitOffsetDays: 15, vetName: 'Dr. Priya Vet', recordType: 'vaccination', notes: 'DHPP booster' },
    ],
    events: [
      { type: 'INTAKE', offsetDays: 45, notes: 'Owner surrender - relocation' },
      { type: 'FOSTER_PLACEMENT', offsetDays: 20, notes: 'Placed with Sarah Lake' },
      { type: 'ADOPTION_PENDING', offsetDays: 5, notes: 'Meet-and-greet completed' },
    ],
  },
  {
    microchip: 'CAT-0002',
    name: 'Whiskers',
    species: 'Cat',
    breed: 'Tabby',
    sex: Sex.FEMALE,
    status: PetStatus.ADOPTED,
    color: 'Orange tabby',
    weightKg: 4.1,
    sterilized: true,
    intakeAtDaysAgo: 60,
    shelterRef: 'north-shelter',
    locationRef: 'north-a1',
    owners: [
      { email: 'ivy.ngo@example.com', role: OwnerRole.FOSTER, isPrimary: false, startDaysAgo: 52, endDaysAgo: 30 },
      { email: 'bob.jones@example.com', role: OwnerRole.OWNER, isPrimary: true, startDaysAgo: 28 },
    ],
    medicalRecords: [
      { visitOffsetDays: 55, vetName: 'Dr. Priya Vet', recordType: 'dental', notes: 'Minor tartar removed' },
    ],
    events: [
      { type: 'INTAKE', offsetDays: 60, notes: 'Transferred from field services' },
      { type: 'FOSTER_PLACEMENT', offsetDays: 52, notes: 'Short-term foster with Ivy Ngo' },
      { type: 'ADOPTION', offsetDays: 28, notes: 'Adopted by Bob Jones' },
    ],
  },
  {
    microchip: 'DOG-0003',
    name: 'Luna',
    species: 'Dog',
    breed: 'Siberian Husky',
    sex: Sex.FEMALE,
    status: PetStatus.ADOPTED,
    color: 'Grey/white',
    weightKg: 18.4,
    sterilized: true,
    intakeAtDaysAgo: 120,
    shelterRef: 'north-shelter',
    locationRef: 'north-foster',
    owners: [
      { email: 'ivy.ngo@example.com', role: OwnerRole.FOSTER, startDaysAgo: 100, endDaysAgo: 35 },
      { email: 'jordan.carey@example.com', role: OwnerRole.OWNER, isPrimary: true, startDaysAgo: 32 },
    ],
    medicalRecords: [
      { visitOffsetDays: 110, vetName: 'Dr. Priya Vet', recordType: 'orthopedic', notes: 'Knee evaluation - cleared' },
    ],
    events: [
      { type: 'INTAKE', offsetDays: 120, notes: 'Field rescue during snowstorm' },
      { type: 'FOSTER_PLACEMENT', offsetDays: 100, notes: 'Medical foster with Ivy' },
      { type: 'ADOPTION', offsetDays: 32, notes: 'Adopted by Jordan Carey' },
    ],
  },
  {
    microchip: 'CAT-0004',
    name: 'Jasper',
    species: 'Cat',
    breed: 'Russian Blue mix',
    sex: Sex.MALE,
    status: PetStatus.AVAILABLE,
    color: 'Blue/grey',
    weightKg: 5.3,
    sterilized: true,
    intakeAtDaysAgo: 25,
    shelterRef: 'central-shelter',
    locationRef: 'central-med',
    owners: [
      { email: 'alice.moreno@example.com', role: OwnerRole.EMERGENCY_CONTACT, isPrimary: false, startDaysAgo: 24 },
    ],
    medicalRecords: [
      { visitOffsetDays: 23, vetName: 'Dr. Priya Vet', recordType: 'respiratory', notes: 'Completed antibiotic course' },
    ],
    events: [
      { type: 'INTAKE', offsetDays: 25, notes: 'Found stray - mild URI' },
      { type: 'MEDICAL', offsetDays: 23, notes: 'Started antibiotics' },
    ],
  },
  {
    microchip: 'DOG-0005',
    name: 'Pepper',
    species: 'Dog',
    breed: 'Mixed Breed',
    sex: Sex.FEMALE,
    status: PetStatus.HOLD,
    color: 'Black/white',
    weightKg: 16,
    sterilized: false,
    intakeAtDaysAgo: 10,
    shelterRef: 'central-shelter',
    locationRef: 'central-rehab',
    notes: 'Behavior hold for decompression plan.',
    owners: [
      { email: 'pawsitive.rescue@example.com', role: OwnerRole.FOSTER, isPrimary: true, startDaysAgo: 3, notes: 'Rescue partner prepping foster team' },
    ],
    medicalRecords: [
      { visitOffsetDays: 9, vetName: 'Dr. Priya Vet', recordType: 'behavior', notes: 'Initial behavior plan created' },
    ],
    events: [
      { type: 'INTAKE', offsetDays: 10, notes: 'Transfer from municipal partner' },
      { type: 'BEHAVIOR_PLAN', offsetDays: 9, notes: 'Started decompression plan' },
    ],
  },
  {
    microchip: 'RAB-0006',
    name: 'Willow',
    species: 'Rabbit',
    breed: 'Lionhead',
    sex: Sex.FEMALE,
    status: PetStatus.FOSTERED,
    color: 'White',
    weightKg: 2.1,
    sterilized: true,
    intakeAtDaysAgo: 32,
    shelterRef: 'west-shelter',
    locationRef: 'west-a1',
    owners: [
      { email: 'emily.foster@example.com', role: OwnerRole.FOSTER, isPrimary: true, startDaysAgo: 15 },
      { email: 'liam.turner@example.com', role: OwnerRole.EMERGENCY_CONTACT, isPrimary: false, startDaysAgo: 15 },
    ],
    medicalRecords: [
      { visitOffsetDays: 28, vetName: 'Dr. Priya Vet', recordType: 'spay', notes: 'Spay follow-up clear' },
    ],
    events: [
      { type: 'INTAKE', offsetDays: 32, notes: 'Owner surrender - allergies' },
      { type: 'FOSTER_PLACEMENT', offsetDays: 15, notes: 'Placed with Emily Foster' },
    ],
  },
  {
    microchip: 'DOG-0007',
    name: 'Arlo',
    species: 'Dog',
    breed: 'Golden Retriever',
    sex: Sex.MALE,
    status: PetStatus.ADOPTED,
    color: 'Golden',
    weightKg: 24,
    sterilized: true,
    intakeAtDaysAgo: 90,
    shelterRef: 'central-shelter',
    locationRef: 'central-a1',
    owners: [
      { email: 'greg.ramirez@example.com', role: OwnerRole.FOSTER, startDaysAgo: 75, endDaysAgo: 20 },
      { email: 'holly.park@example.com', role: OwnerRole.OWNER, isPrimary: true, startDaysAgo: 18 },
    ],
    medicalRecords: [
      { visitOffsetDays: 85, vetName: 'Dr. Priya Vet', recordType: 'allergy', notes: 'Seasonal allergies treated' },
    ],
    events: [
      { type: 'INTAKE', offsetDays: 90, notes: 'Owner medical hardship' },
      { type: 'FOSTER_PLACEMENT', offsetDays: 75, notes: 'With Greg Ramirez for training' },
      { type: 'ADOPTION', offsetDays: 18, notes: 'Adopted by Holly Park' },
    ],
  },
  {
    microchip: 'CAT-0008',
    name: 'Nova',
    species: 'Cat',
    breed: 'Siamese mix',
    sex: Sex.FEMALE,
    status: PetStatus.AVAILABLE,
    color: 'Seal point',
    weightKg: 3.8,
    sterilized: true,
    intakeAtDaysAgo: 14,
    shelterRef: 'west-shelter',
    locationRef: 'west-training',
    owners: [
      { email: 'noah.reed@example.com', role: OwnerRole.FOSTER, startDaysAgo: 12, endDaysAgo: 2 },
      { email: 'david.chen@example.com', role: OwnerRole.EMERGENCY_CONTACT, startDaysAgo: 12 },
    ],
    medicalRecords: [
      { visitOffsetDays: 12, vetName: 'Dr. Priya Vet', recordType: 'vaccination', notes: 'FVRCP booster' },
    ],
    events: [
      { type: 'INTAKE', offsetDays: 14, notes: 'Good Samaritan intake' },
      { type: 'FOSTER_PLACEMENT', offsetDays: 12, notes: 'Short temp foster' },
    ],
  },
]

const demoUsers: DemoUserSeed[] = [
  { email: 'system.supervisor@example.com', name: 'Sylvia System', roles: ['system_admin'] },
  { email: 'ops.admin@example.com', name: 'Oscar Operations', roles: ['admin'] },
  { email: 'shelter.lead@example.com', name: 'Lena Shelter', roles: ['shelter_admin'] },
  { email: 'staff.manager@example.com', name: 'Marco Manager', roles: ['staff_manager'] },
  { email: 'veterinarian@example.com', name: 'Dr. Priya Vet', roles: ['veterinarian'] },
  { email: 'animal.staff@example.com', name: 'Nina Staff', roles: ['staff'] },
  { email: 'volunteer.care@example.com', name: 'Val Volunteer', roles: ['volunteer'] },
  { email: 'foster.portal@example.com', name: 'Frankie Foster', roles: ['owner'] },
]

async function upsertDemoUsers(passwordHash: string) {
  for (const userSeed of demoUsers) {
    const user = await prisma.user.upsert({
      where: { email: userSeed.email },
      update: {
        name: userSeed.name,
        passwordHash,
        emailVerified: new Date(),
        metadata: userSeed.metadata ?? undefined,
      },
      create: {
        email: userSeed.email,
        name: userSeed.name,
        passwordHash,
        emailVerified: new Date(),
        metadata: userSeed.metadata ?? undefined,
      },
    })

    await prisma.userRole.deleteMany({ where: { userId: user.id } })
    for (const roleName of userSeed.roles) {
      const role = await prisma.role.findUnique({ where: { name: roleName } })
      if (!role) continue
      await prisma.userRole.create({ data: { userId: user.id, roleId: role.id } })
    }
  }
}

async function main() {
  // Seed base roles for RBAC (system_admin > admin > shelter_admin > veterinarian > staff_manager > staff > staff_assistant > volunteer > owner)
  const roles = [
    { name: 'system_admin', rank: 100, description: 'Full system administrator' },
    { name: 'admin', rank: 80, description: 'Organization administrator' },
    { name: 'shelter_admin', rank: 60, description: 'Shelter administrator' },
    { name: 'veterinarian', rank: 55, description: 'Veterinary professional' },
    { name: 'staff_manager', rank: 50, description: 'Management-level shelter staff' },
    { name: 'staff', rank: 40, description: 'Shelter staff' },
    { name: 'staff_assistant', rank: 30, description: 'Assistant or junior shelter staff' },
    { name: 'volunteer', rank: 20, description: 'Volunteer' },
    { name: 'owner', rank: 10, description: 'Pet owner portal user' },
  ]
  for (const r of roles) {
    await prisma.role.upsert({
      where: { name: r.name },
      update: { rank: r.rank, description: r.description },
      create: r,
    })
  }

  // Seed permissions
  const permissions = [
    'pets.read','pets.write','shelters.read','shelters.write','locations.read','locations.write','owners.read','owners.write','medical.read','medical.write','events.read','events.write'
  ]
  for (const name of permissions) {
    await prisma.permission.upsert({ where: { name }, update: {}, create: { name } })
  }

  // Attach permissions to roles
  async function grant(roleName: string, permNames: string[]) {
    const role = await prisma.role.findUnique({ where: { name: roleName } })
    if (!role) return
    for (const p of permNames) {
      const perm = await prisma.permission.findUnique({ where: { name: p } })
      if (!perm) continue
      await prisma.rolePermission.upsert({
        where: { roleId_permissionId: { roleId: role.id, permissionId: perm.id } as any },
        update: {},
        create: { roleId: role.id, permissionId: perm.id },
      })
    }
  }

  // Owner (formerly 'user'): read-only baseline
  await grant('owner', ['pets.read','shelters.read','locations.read','owners.read','medical.read','events.read'])
  // Volunteer: conservative read-only for now (same as owner); refine later
  await grant('volunteer', ['pets.read','shelters.read','locations.read','owners.read','medical.read','events.read'])
  // Staff assistant: mostly read-only; allow recording events
  await grant('staff_assistant', ['pets.read','shelters.read','locations.read','owners.read','medical.read','events.read','events.write'])
  // Staff: operational writes (same as previous staff mapping)
  await grant('staff', ['pets.read','pets.write','shelters.read','locations.read','locations.write','owners.read','owners.write','medical.read','medical.write','events.read','events.write'])
  // Staff manager: same as staff for now; refine later with additional privileges
  await grant('staff_manager', ['pets.read','pets.write','shelters.read','locations.read','locations.write','owners.read','owners.write','medical.read','medical.write','events.read','events.write'])
  // Veterinarian: focus on medical writes + relevant reads
  await grant('veterinarian', ['pets.read','owners.read','medical.read','medical.write','events.read'])
  // Admin tiers: full access
  await grant('shelter_admin', permissions)
  await grant('admin', permissions)
  await grant('system_admin', permissions)

  // Seed shelters + locations
  const shelterMap = new Map<string, any>()
  const locationMap = new Map<string, any>()
  for (const shelterSeed of shelterSeeds) {
    const shelter = await prisma.shelter.upsert({
      where: { id: shelterSeed.id },
      update: {
        name: shelterSeed.name,
        address: shelterSeed.address,
        phone: shelterSeed.phone ?? null,
        email: shelterSeed.email ?? null,
        capacity: shelterSeed.capacity ?? null,
        notes: shelterSeed.notes ?? null,
      },
      create: {
        id: shelterSeed.id,
        name: shelterSeed.name,
        address: shelterSeed.address,
        phone: shelterSeed.phone ?? null,
        email: shelterSeed.email ?? null,
        capacity: shelterSeed.capacity ?? null,
        notes: shelterSeed.notes ?? null,
      },
    })
    shelterMap.set(shelterSeed.id, shelter)

    for (const locationSeed of shelterSeed.locations) {
      const location = await prisma.location.upsert({
        where: { id: locationSeed.id },
        update: {
          shelterId: shelter.id,
          code: locationSeed.code,
          description: locationSeed.description ?? null,
          capacity: locationSeed.capacity ?? null,
          notes: locationSeed.notes ?? null,
        },
        create: {
          id: locationSeed.id,
          shelterId: shelter.id,
          code: locationSeed.code,
          description: locationSeed.description ?? null,
          capacity: locationSeed.capacity ?? null,
          notes: locationSeed.notes ?? null,
        },
      })
      locationMap.set(locationSeed.id, location)
    }
  }

  // owners
  const ownerMap = new Map<string, any>()
  for (const ownerSeed of ownerSeeds) {
    const owner = await prisma.owner.upsert({
      where: { email: ownerSeed.email },
      update: {
        firstName: ownerSeed.firstName,
        lastName: ownerSeed.lastName,
        phone: ownerSeed.phone ?? null,
        type: ownerSeed.type ?? null,
        address: ownerSeed.address ?? null,
        notes: ownerSeed.notes ?? null,
      },
      create: {
        firstName: ownerSeed.firstName,
        lastName: ownerSeed.lastName,
        email: ownerSeed.email,
        phone: ownerSeed.phone ?? null,
        type: ownerSeed.type ?? null,
        address: ownerSeed.address ?? null,
        notes: ownerSeed.notes ?? null,
      },
    })
    ownerMap.set(ownerSeed.email, owner)
  }

  for (const petSeed of petSeeds) {
    const shelterId = petSeed.shelterRef ? shelterMap.get(petSeed.shelterRef)?.id ?? null : null
    const locationId = petSeed.locationRef ? locationMap.get(petSeed.locationRef)?.id ?? null : null
    const intakeAt = petSeed.intakeAt ?? (petSeed.intakeAtDaysAgo !== undefined ? daysAgo(petSeed.intakeAtDaysAgo) : new Date())

    const pet = await prisma.pet.upsert({
      where: { microchip: petSeed.microchip },
      update: {
        name: petSeed.name,
        species: petSeed.species,
        breed: petSeed.breed ?? null,
        sex: petSeed.sex,
        status: petSeed.status,
        color: petSeed.color ?? null,
        weightKg: petSeed.weightKg ?? null,
        sterilized: petSeed.sterilized ?? false,
        notes: petSeed.notes ?? null,
        intakeAt,
        shelterId,
        locationId,
      },
      create: {
        name: petSeed.name,
        species: petSeed.species,
        breed: petSeed.breed ?? null,
        sex: petSeed.sex,
        status: petSeed.status,
        color: petSeed.color ?? null,
        weightKg: petSeed.weightKg ?? null,
        sterilized: petSeed.sterilized ?? false,
        notes: petSeed.notes ?? null,
        intakeAt,
        shelterId,
        locationId,
        microchip: petSeed.microchip,
      },
    })

    await prisma.petOwner.deleteMany({ where: { petId: pet.id } })
    for (const ownerRef of petSeed.owners) {
      const owner = ownerMap.get(ownerRef.email)
      if (!owner) continue
      const startDate = ownerRef.startDate ?? (ownerRef.startDaysAgo !== undefined ? daysAgo(ownerRef.startDaysAgo) : new Date())
      const endDate = ownerRef.endDate ?? (ownerRef.endDaysAgo !== undefined ? daysAgo(ownerRef.endDaysAgo) : null)

      await prisma.petOwner.create({
        data: {
          petId: pet.id,
          ownerId: owner.id,
          role: ownerRef.role,
          isPrimary: ownerRef.isPrimary ?? false,
          startDate,
          endDate,
          notes: ownerRef.notes ?? null,
        },
      })
    }

    await prisma.medicalRecord.deleteMany({ where: { petId: pet.id } })
    for (const record of petSeed.medicalRecords ?? []) {
      await prisma.medicalRecord.create({
        data: {
          petId: pet.id,
          visitDate: daysAgo(record.visitOffsetDays),
          vetName: record.vetName ?? null,
          recordType: record.recordType ?? null,
          notes: record.notes ?? null,
        },
      })
    }

    await prisma.event.deleteMany({ where: { petId: pet.id } })
    for (const evt of petSeed.events ?? []) {
      const fromShelterId = evt.fromShelterRef === null ? null : evt.fromShelterRef ? shelterMap.get(evt.fromShelterRef)?.id ?? null : null
      const toShelterId = evt.toShelterRef === null ? null : evt.toShelterRef ? shelterMap.get(evt.toShelterRef)?.id ?? null : null
      await prisma.event.create({
        data: {
          petId: pet.id,
          type: evt.type,
          occurredAt: daysAgo(evt.offsetDays),
          fromShelterId,
          toShelterId,
          notes: evt.notes ?? null,
        },
      })
    }
  }

  // Optional seed user for testing admin access
  const adminEmail = (process as any)?.env?.SEED_ADMIN_EMAIL || 'admin@example.com'
  const adminPass = (process as any)?.env?.SEED_ADMIN_PASSWORD || 'Admin123!@#'
  const existing = await prisma.user.findUnique({ where: { email: adminEmail } })
  if (!existing) {
    // Use a light hash cost for seeding only
    const passwordHash = await (argon2 as any).hash(adminPass, { type: (argon2 as any).argon2id })
    const user = await prisma.user.create({ data: { email: adminEmail, passwordHash, name: 'Seed Admin', emailVerified: new Date() } })
    const sysAdmin = await prisma.role.findUnique({ where: { name: 'system_admin' } })
    if (sysAdmin) {
      await prisma.userRole.create({ data: { userId: user.id, roleId: sysAdmin.id } })
    }
    console.log(`Seeded admin user: ${adminEmail} / ${adminPass}`)
  }

  const demoPassword = (process as any)?.env?.SEED_DEMO_PASSWORD || 'DemoPass123!'
  const demoPasswordHash = await (argon2 as any).hash(demoPassword, { type: (argon2 as any).argon2id })
  await upsertDemoUsers(demoPasswordHash)
  console.log(`Seeded demo users with password: ${demoPassword}`)

  // Seed default application settings if not present
  const defaultSettings: Record<string, Record<string, any>> = {
    general: {
      siteName: 'Pet Shelter Registry System',
      environment: (process as any)?.env?.NODE_ENV || 'development',
    },
    monitoring: {
      chartsRefreshSec: 15,
      retentionDays: 7,
    },
    auth: {
      google: true,
      github: true,
    },
    docs: {
      showPublicDocsLink: true,
    },
    security: {
      requireEmailVerification: true,
      // 30 days in minutes for refresh/session max-age fallback
      sessionMaxAgeMin: 30 * 24 * 60,
    },
    audit: { ...DEFAULT_AUDIT_SETTINGS },
  }

  for (const [category, entries] of Object.entries(defaultSettings)) {
    for (const [key, value] of Object.entries(entries)) {
      const existing = await prisma.setting.findUnique({ where: { category_key: { category, key } } })
      if (!existing) {
        await prisma.setting.create({ data: { category, key, value } })
      }
    }
  }

  type MenuNode = {
    title: string
    url?: string | null
    icon?: string | null
    target?: string | null
    external?: boolean | null
    order?: number | null
    meta?: Record<string, any> | null
    children?: MenuNode[]
  }

  type MenuSeed = {
    name: string
    title: string
    description?: string | null
    locale?: string | null
    isActive?: boolean
    items: MenuNode[]
  }

  const VOLUNTEER_AND_UP = ['volunteer', 'staff_assistant', 'staff', 'staff_manager', 'veterinarian', 'shelter_admin', 'admin', 'system_admin']
  const STAFF_OR_ABOVE = ['staff', 'staff_manager', 'veterinarian', 'shelter_admin', 'admin', 'system_admin']
  const MANAGER_OR_ABOVE = ['staff_manager', 'shelter_admin', 'admin', 'system_admin']
  const SHELTER_ADMIN_OR_ABOVE = ['shelter_admin', 'admin', 'system_admin']
  const ADMIN_ONLY = ['admin', 'system_admin']

  async function syncMenu(seed: MenuSeed) {
    const menu = await prisma.menu.upsert({
      where: { name: seed.name },
      update: {
        title: seed.title,
        description: seed.description ?? null,
        locale: seed.locale ?? null,
        isActive: seed.isActive ?? true,
      },
      create: {
        name: seed.name,
        title: seed.title,
        description: seed.description ?? null,
        locale: seed.locale ?? null,
        isActive: seed.isActive ?? true,
      },
    })

    await prisma.menuItem.deleteMany({ where: { menuId: menu.id } })

    async function createNodes(parentId: string | null, nodes: MenuNode[]) {
      for (const node of nodes) {
        const item = await prisma.menuItem.create({
          data: {
            menuId: menu.id,
            parentId,
            title: node.title,
            url: node.url ?? null,
            icon: node.icon ?? null,
            target: node.target ?? null,
            external: node.external ?? false,
            order: node.order ?? 0,
            meta: node.meta ?? undefined,
            isVisible: true,
            isPublished: true,
            locale: seed.locale ?? null,
          },
        })
        if (node.children && node.children.length) {
          await createNodes(item.id, node.children)
        }
      }
    }

    await createNodes(null, seed.items)
    console.log(`Seeded menu '${seed.name}' with ${seed.items.length} top-level group(s)`)
  }

  const adminMenuItems: MenuNode[] = [
    {
      title: 'Overview',
      icon: 'LayoutDashboard',
      order: 0,
      meta: { requiresRoles: VOLUNTEER_AND_UP },
      children: [
        { title: 'Dashboard', url: '/dashboard', order: 0, icon: 'Gauge', meta: { requiresRoles: VOLUNTEER_AND_UP } },
        { title: 'Alerts', url: '/alerts', order: 10, icon: 'BellRing', meta: { requiresPermissions: ['events.read'] } },
        { title: 'Upcoming Events', url: '/events/upcoming', order: 20, icon: 'CalendarRange', meta: { requiresPermissions: ['events.read'] } },
      ],
    },
    {
      title: 'Animal Management',
      icon: 'PawPrint',
      order: 10,
      meta: { requiresPermissions: ['pets.read'] },
      children: [
        { title: 'All Animals', url: '/animals', order: 0, icon: 'List', meta: { requiresPermissions: ['pets.read'] } },
        { title: 'Intake', url: '/animals/intake', order: 10, icon: 'LogIn', meta: { requiresPermissions: ['pets.write'] } },
        { title: 'Adoptions', url: '/animals/adoptions', order: 20, icon: 'UsersRound', meta: { requiresPermissions: ['pets.read', 'owners.read'] } },
        { title: 'Medical Records', url: '/animals/medical', order: 30, icon: 'Stethoscope', meta: { requiresPermissions: ['medical.read'] } },
        { title: 'Events Log', url: '/animals/events', order: 40, icon: 'History', meta: { requiresPermissions: ['events.read'] } },
      ],
    },
    {
      title: 'People & Relationships',
      icon: 'Users',
      order: 20,
      meta: { requiresPermissions: ['owners.read'] },
      children: [
        { title: 'Owners', url: '/people/owners', order: 0, icon: 'User', meta: { requiresPermissions: ['owners.read'] } },
        { title: 'Fosters', url: '/people/fosters', order: 10, icon: 'Home', meta: { requiresPermissions: ['owners.read'] } },
        { title: 'Volunteers', url: '/people/volunteers', order: 20, icon: 'Handshake', meta: { requiresRoles: VOLUNTEER_AND_UP } },
        { title: 'Contacts', url: '/people/contacts', order: 30, icon: 'BookUser', meta: { requiresPermissions: ['owners.read'] } },
      ],
    },
    {
      title: 'Shelters & Facilities',
      icon: 'Building2',
      order: 30,
      meta: { requiresPermissions: ['shelters.read'] },
      children: [
        { title: 'Locations', url: '/facilities/locations', order: 0, icon: 'MapPin', meta: { requiresPermissions: ['locations.read'] } },
        { title: 'Capacity', url: '/facilities/capacity', order: 10, icon: 'BarChart3', meta: { requiresPermissions: ['shelters.read'] } },
        { title: 'Maintenance', url: '/facilities/maintenance', order: 20, icon: 'Wrench', meta: { requiresPermissions: ['locations.write'] } },
        { title: 'Inventory', url: '/facilities/inventory', order: 30, icon: 'Boxes', meta: { requiresPermissions: ['shelters.write'] } },
      ],
    },
    {
      title: 'Scheduling & Tasks',
      icon: 'ClipboardList',
      order: 40,
      meta: { requiresRoles: STAFF_OR_ABOVE },
      children: [
        { title: 'Calendar', url: '/schedule/calendar', order: 0, icon: 'CalendarRange', meta: { requiresRoles: STAFF_OR_ABOVE } },
        { title: 'Shifts', url: '/schedule/shifts', order: 10, icon: 'ClipboardClock', meta: { requiresRoles: MANAGER_OR_ABOVE } },
        { title: 'Follow-ups', url: '/schedule/follow-ups', order: 20, icon: 'CheckSquare', meta: { requiresPermissions: ['events.read'] } },
        { title: 'Reminders', url: '/schedule/reminders', order: 30, icon: 'AlarmClock', meta: { requiresPermissions: ['events.write'] } },
      ],
    },
    {
      title: 'Reporting & Analytics',
      icon: 'PieChart',
      order: 50,
      meta: { requiresPermissions: ['pets.read'] },
      children: [
        { title: 'Outcomes', url: '/reports/outcomes', order: 0, icon: 'PieChart', meta: { requiresPermissions: ['pets.read'] } },
        { title: 'Intake vs Adoption', url: '/reports/intake-vs-adoption', order: 10, icon: 'TrendingUp', meta: { requiresPermissions: ['pets.read'] } },
        { title: 'Compliance', url: '/reports/compliance', order: 20, icon: 'ShieldAlert', meta: { requiresPermissions: ['medical.read'] } },
        { title: 'Exports', url: '/reports/exports', order: 30, icon: 'FileDown', meta: { requiresRoles: MANAGER_OR_ABOVE } },
      ],
    },
    {
      title: 'Projects',
      icon: 'Briefcase',
      order: 55,
      meta: { requiresRoles: MANAGER_OR_ABOVE },
      children: [
        { title: 'Active Projects', url: '/projects/active', order: 0, icon: 'ListChecks', meta: { requiresRoles: MANAGER_OR_ABOVE } },
        { title: 'New Project', url: '/projects/new', order: 10, icon: 'PlusSquare', meta: { requiresRoles: SHELTER_ADMIN_OR_ABOVE } },
        { title: 'Archived Projects', url: '/projects/archived', order: 20, icon: 'Archive', meta: { requiresRoles: MANAGER_OR_ABOVE } },
      ],
    },
    {
      title: 'Admin',
      icon: 'Settings2',
      order: 60,
      meta: { requiresRoles: ADMIN_ONLY },
      children: [
        { title: 'Users', url: '/admin/users', order: 0, icon: 'Users', meta: { requiresRoles: ADMIN_ONLY } },
  { title: 'Navigation Builder', url: '/admin/navigation-builder', order: 10, icon: 'PanelsTopLeft', meta: { requiresRoles: ADMIN_ONLY } },
        { title: 'Integrations', url: '/admin/integrations', order: 20, icon: 'Plug', meta: { requiresRoles: ADMIN_ONLY } },
        { title: 'Documentation', url: '/admin/docs', order: 30, icon: 'BookOpen', meta: { requiresRoles: ADMIN_ONLY } },
        { title: 'System Logs', url: '/admin/system-logs', order: 40, icon: 'ScrollText', meta: { requiresRoles: ADMIN_ONLY } },
      ],
    },
  ]

  const settingsMenuSeed: MenuSeed = {
    name: 'settings_main',
    title: 'Settings',
    description: 'Context-aware settings sections for administrators and staff',
    items: [
      {
        title: 'Account & Profile',
        order: 0,
        children: [
          { title: 'Profile', url: '/settings/account/profile', order: 0, meta: { settingsRoute: '/settings/account/profile' } },
          { title: 'Security', url: '/settings/account/security', order: 1 },
          { title: 'Notifications', url: '/settings/account/notifications', order: 2 },
          { title: 'Connected Apps', url: '/settings/account/connected-apps', order: 3 },
        ],
      },
      {
        title: 'Organization',
        order: 100,
        children: [
          { title: 'Organization Settings', url: '/settings/organization', order: 0, meta: { settingsCategory: 'general', requiresRoles: ADMIN_ONLY } },
          { title: 'Branding', url: '/settings/organization/branding', order: 1 },
          { title: 'Locations', url: '/settings/organization/locations', order: 2 },
          { title: 'Teams & Departments', url: '/settings/organization/teams', order: 3 },
        ],
      },
      {
        title: 'Security & Access',
        order: 200,
        children: [
          { title: 'Authentication', url: '/settings/security/authentication', order: 0, meta: { settingsCategory: 'auth', requiresRoles: ADMIN_ONLY } },
          { title: 'Session Policies', url: '/settings/security/sessions', order: 1, meta: { settingsCategory: 'security', requiresRoles: ADMIN_ONLY } },
          { title: 'Roles & Permissions', url: '/settings/security/roles', order: 2 },
          { title: 'Audit Logs', url: '/settings/security/audit-logs', order: 3 },
        ],
      },
      {
        title: 'Integrations & API',
        order: 300,
        children: [
          { title: 'Integration Catalog', url: '/settings/integrations/catalog', order: 0 },
          { title: 'API Access', url: '/settings/integrations/api', order: 1 },
          { title: 'Webhooks', url: '/settings/integrations/webhooks', order: 2 },
          { title: 'Developer Console', url: '/settings/integrations/dev-console', order: 3 },
        ],
      },
      {
        title: 'Billing & Subscription',
        order: 400,
        children: [
          { title: 'Plan & Usage', url: '/settings/billing/plan', order: 0 },
          { title: 'Invoices', url: '/settings/billing/invoices', order: 1 },
          { title: 'Payment Methods', url: '/settings/billing/payment-methods', order: 2 },
        ],
      },
      {
        title: 'Monitoring & Reliability',
        order: 500,
        children: [
          { title: 'System Health', url: '/settings/monitoring/health', order: 0, meta: { settingsCategory: 'monitoring', requiresRoles: ADMIN_ONLY } },
          { title: 'Alerting', url: '/settings/monitoring/alerting', order: 1 },
          { title: 'Data Retention', url: '/settings/monitoring/data-retention', order: 2 },
        ],
      },
      {
        title: 'Documentation & Support',
        order: 600,
        children: [
          { title: 'Knowledge Base', url: '/settings/docs/knowledge-base', order: 0, meta: { settingsCategory: 'docs', requiresRoles: ADMIN_ONLY } },
          { title: 'Release Notes', url: '/settings/docs/release-notes', order: 1 },
          { title: 'Support Center', url: '/settings/docs/support', order: 2 },
        ],
      },
    ],
  }

  const menusToSeed: MenuSeed[] = [
    settingsMenuSeed,
    {
      name: 'main',
      title: 'Main Navigation',
      description: 'Default navigation menu',
      items: adminMenuItems,
    },
  ]

  for (const menu of menusToSeed) {
    await syncMenu(menu)
  }
}

main()
  .catch(e => {
    console.error(e)
    ;(globalThis as any).process?.exit?.(1)
  })
  .finally(async () => {
    await prisma.$disconnect()
  })
