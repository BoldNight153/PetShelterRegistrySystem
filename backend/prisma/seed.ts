import { PrismaClient } from '@prisma/client';
const prisma: any = new PrismaClient();

async function main() {
  // Seed base roles for RBAC (system_admin > admin > shelter_admin > staff > user)
  const roles = [
    { name: 'system_admin', rank: 100, description: 'Full system administrator' },
    { name: 'admin', rank: 80, description: 'Organization administrator' },
    { name: 'shelter_admin', rank: 60, description: 'Shelter administrator' },
    { name: 'staff', rank: 40, description: 'Shelter staff' },
    { name: 'user', rank: 10, description: 'Regular user' },
  ];
  for (const r of roles) {
    await prisma.role.upsert({
      where: { name: r.name },
      update: { rank: r.rank, description: r.description },
      create: r,
    });
  }

  // Seed permissions
  const permissions = [
    'pets.read','pets.write','shelters.read','shelters.write','locations.read','locations.write','owners.read','owners.write','medical.read','medical.write','events.read','events.write'
  ];
  for (const name of permissions) {
    await prisma.permission.upsert({ where: { name }, update: {}, create: { name } });
  }

  // Attach permissions to roles
  async function grant(roleName: string, permNames: string[]) {
    const role = await prisma.role.findUnique({ where: { name: roleName } });
    if (!role) return;
    for (const p of permNames) {
      const perm = await prisma.permission.findUnique({ where: { name: p } });
      if (!perm) continue;
      await prisma.rolePermission.upsert({
        where: { roleId_permissionId: { roleId: role.id, permissionId: perm.id } as any },
        update: {},
        create: { roleId: role.id, permissionId: perm.id },
      });
    }
  }

  await grant('user', ['pets.read','shelters.read','locations.read','owners.read','medical.read','events.read']);
  await grant('staff', ['pets.read','pets.write','shelters.read','locations.read','locations.write','owners.read','owners.write','medical.read','medical.write','events.read','events.write']);
  await grant('shelter_admin', permissions);
  await grant('admin', permissions);
  await grant('system_admin', permissions);

  // create shelters
  const s1 = await prisma.shelter.upsert({ where: { id: 'central-shelter' }, update: {}, create: { id: 'central-shelter', name: 'Central Shelter', address: { city: 'Metropolis' }, phone: '555-1234' } });
  const s2 = await prisma.shelter.upsert({ where: { id: 'north-shelter' }, update: {}, create: { id: 'north-shelter', name: 'North Shelter', address: { city: 'North Town' }, phone: '555-5678' } });

  // locations
  const l1 = await prisma.location.upsert({ where: { id: 'central-a1' }, update: {}, create: { id: 'central-a1', shelterId: s1.id, code: 'A-1', description: 'Front row cages' } });
  const l2 = await prisma.location.upsert({ where: { id: 'central-a2' }, update: {}, create: { id: 'central-a2', shelterId: s1.id, code: 'A-2', description: 'Isolation room' } });

  // owners
  const o1 = await prisma.owner.upsert({ where: { email: 'alice@example.com' }, update: {}, create: { firstName: 'Alice', lastName: 'Smith', email: 'alice@example.com' } });
  const o2 = await prisma.owner.upsert({ where: { email: 'bob@example.com' }, update: {}, create: { firstName: 'Bob', lastName: 'Jones', email: 'bob@example.com', phone: '555-9876' } });

  // pets
  const p1 = await prisma.pet.upsert({ where: { microchip: 'MILO-000' }, update: {}, create: { name: 'Milo', species: 'Dog', breed: 'Beagle', sex: 'MALE', intakeAt: new Date(), shelterId: s1.id, locationId: l1.id, microchip: 'MILO-000' } });
  const p2 = await prisma.pet.upsert({ where: { microchip: 'WHISKERS-000' }, update: {}, create: { name: 'Whiskers', species: 'Cat', breed: 'Tabby', sex: 'FEMALE', intakeAt: new Date(), shelterId: s1.id, locationId: l2.id, microchip: 'WHISKERS-000' } });

  await prisma.petOwner.upsert({ where: { id: 'p1-o1' }, update: {}, create: { id: 'p1-o1', petId: p1.id, ownerId: o1.id, role: 'FOSTER', isPrimary: true } });
  await prisma.petOwner.upsert({ where: { id: 'p2-o2' }, update: {}, create: { id: 'p2-o2', petId: p2.id, ownerId: o2.id, role: 'OWNER', isPrimary: true } });

  await prisma.medicalRecord.upsert({ where: { id: 'm1' }, update: {}, create: { id: 'm1', petId: p1.id, vetName: 'Dr. Vet', recordType: 'vaccine', notes: 'Rabies shot' } });
}

main()
  .catch(e => {
    console.error(e);
    (globalThis as any).process?.exit?.(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
