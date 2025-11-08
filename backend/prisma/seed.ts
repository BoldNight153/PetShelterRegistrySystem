import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
// Declare minimal process type to appease TS in environments without @types/node
declare const process: { env: Record<string, string | undefined> };
const prisma: any = new PrismaClient();

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

  // Owner (formerly 'user'): read-only baseline
  await grant('owner', ['pets.read','shelters.read','locations.read','owners.read','medical.read','events.read']);
  // Volunteer: conservative read-only for now (same as owner); refine later
  await grant('volunteer', ['pets.read','shelters.read','locations.read','owners.read','medical.read','events.read']);
  // Staff assistant: mostly read-only; allow recording events
  await grant('staff_assistant', ['pets.read','shelters.read','locations.read','owners.read','medical.read','events.read','events.write']);
  // Staff: operational writes (same as previous staff mapping)
  await grant('staff', ['pets.read','pets.write','shelters.read','locations.read','locations.write','owners.read','owners.write','medical.read','medical.write','events.read','events.write']);
  // Staff manager: same as staff for now; refine later with additional privileges
  await grant('staff_manager', ['pets.read','pets.write','shelters.read','locations.read','locations.write','owners.read','owners.write','medical.read','medical.write','events.read','events.write']);
  // Veterinarian: focus on medical writes + relevant reads
  await grant('veterinarian', ['pets.read','owners.read','medical.read','medical.write','events.read']);
  // Admin tiers: full access
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

  // Optional seed user for testing admin access
  const adminEmail = (process as any)?.env?.SEED_ADMIN_EMAIL || 'admin@example.com';
  const adminPass = (process as any)?.env?.SEED_ADMIN_PASSWORD || 'Admin123!@#';
  const existing = await prisma.user.findUnique({ where: { email: adminEmail } });
  if (!existing) {
    // Use a light hash cost for seeding only
  const passwordHash = await (argon2 as any).hash(adminPass, { type: (argon2 as any).argon2id });
    const user = await prisma.user.create({ data: { email: adminEmail, passwordHash, name: 'Seed Admin', emailVerified: new Date() } });
    const sysAdmin = await prisma.role.findUnique({ where: { name: 'system_admin' } });
    if (sysAdmin) {
      await prisma.userRole.create({ data: { userId: user.id, roleId: sysAdmin.id } });
    }
    console.log(`Seeded admin user: ${adminEmail} / ${adminPass}`);
  }

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
  };

  for (const [category, entries] of Object.entries(defaultSettings)) {
    for (const [key, value] of Object.entries(entries)) {
      const existing = await prisma.setting.findUnique({ where: { category_key: { category, key } } });
      if (!existing) {
        await prisma.setting.create({ data: { category, key, value } });
      }
    }
  }

  type MenuNode = {
    title: string;
    url?: string | null;
    icon?: string | null;
    target?: string | null;
    external?: boolean | null;
    order?: number | null;
    meta?: Record<string, any> | null;
    children?: MenuNode[];
  };

  type MenuSeed = {
    name: string;
    title: string;
    description?: string | null;
    locale?: string | null;
    isActive?: boolean;
    items: MenuNode[];
  };

  const VOLUNTEER_AND_UP = ['volunteer', 'staff_assistant', 'staff', 'staff_manager', 'veterinarian', 'shelter_admin', 'admin', 'system_admin'];
  const STAFF_OR_ABOVE = ['staff', 'staff_manager', 'veterinarian', 'shelter_admin', 'admin', 'system_admin'];
  const MANAGER_OR_ABOVE = ['staff_manager', 'shelter_admin', 'admin', 'system_admin'];
  const SHELTER_ADMIN_OR_ABOVE = ['shelter_admin', 'admin', 'system_admin'];
  const ADMIN_ONLY = ['admin', 'system_admin'];

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
    });

    await prisma.menuItem.deleteMany({ where: { menuId: menu.id } });

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
        });
        if (node.children && node.children.length) {
          await createNodes(item.id, node.children);
        }
      }
    }

    await createNodes(null, seed.items);
    console.log(`Seeded menu '${seed.name}' with ${seed.items.length} top-level group(s)`);
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
      title: 'Admin & Settings',
      icon: 'Settings2',
      order: 60,
      meta: { requiresRoles: ADMIN_ONLY },
      children: [
        { title: 'Users & Roles', url: '/settings/users', order: 0, icon: 'Shield', meta: { requiresRoles: ADMIN_ONLY } },
        { title: 'Navigation Builder', url: '/settings/navigation', order: 10, icon: 'PanelsTopLeft', meta: { requiresRoles: ADMIN_ONLY } },
        { title: 'Integrations', url: '/settings/integrations', order: 20, icon: 'Plug', meta: { requiresRoles: ADMIN_ONLY } },
        { title: 'Organization Settings', url: '/settings/general', order: 30, icon: 'SlidersHorizontal', meta: { requiresRoles: ADMIN_ONLY } },
        { title: 'Documentation', url: '/docs', order: 40, icon: 'BookOpen', meta: { requiresRoles: ADMIN_ONLY } },
        { title: 'System Logs', url: '/settings/logs', order: 50, icon: 'ScrollText', meta: { requiresRoles: ADMIN_ONLY } },
      ],
    },
  ];

  const menusToSeed: MenuSeed[] = [
    {
      name: 'admin_main',
      title: 'Admin Navigation',
      description: 'Primary navigation for the administration console',
      items: adminMenuItems,
    },
    {
      name: 'test_main',
      title: 'Dev Preview Navigation',
      description: 'Sample data served by /menus/test_main for frontend testing',
      items: adminMenuItems,
    },
    {
      name: 'main',
      title: 'Main Navigation',
      description: 'Default navigation menu',
      items: adminMenuItems,
    },
  ];

  for (const menu of menusToSeed) {
    await syncMenu(menu);
  }
}

main()
  .catch(e => {
    console.error(e);
    (globalThis as any).process?.exit?.(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
