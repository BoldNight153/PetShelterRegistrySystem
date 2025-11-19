"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const client_1 = require("@prisma/client");
const prisma = new client_1.PrismaClient();
async function main() {
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
    // Seed default `main` menu and items for development
    const mainMenu = await prisma.menu.upsert({ where: { name: 'main' }, update: { title: 'Main Navigation', isActive: true }, create: { name: 'main', title: 'Main Navigation', description: 'Primary site navigation', isActive: true } });
    const existingMenuItems = await prisma.menuItem.findMany({ where: { menuId: mainMenu.id } });
    if (!existingMenuItems.length) {
        const playground = await prisma.menuItem.create({ data: { menuId: mainMenu.id, title: 'Playground', url: '#', order: 0 } });
        await prisma.menuItem.createMany({ data: [
            { menuId: mainMenu.id, parentId: playground.id, title: 'History', url: '#', order: 0 },
            { menuId: mainMenu.id, parentId: playground.id, title: 'Starred', url: '#', order: 1 },
            { menuId: mainMenu.id, parentId: playground.id, title: 'Settings', url: '#', order: 2 },
        ] });
        const docs = await prisma.menuItem.create({ data: { menuId: mainMenu.id, title: 'Documentation', url: '#', order: 10 } });
        await prisma.menuItem.createMany({ data: [
            { menuId: mainMenu.id, parentId: docs.id, title: 'Introduction', url: '#', order: 0 },
            { menuId: mainMenu.id, parentId: docs.id, title: 'Get Started', url: '#', order: 1 },
            { menuId: mainMenu.id, parentId: docs.id, title: 'Tutorials', url: '#', order: 2 },
            { menuId: mainMenu.id, parentId: docs.id, title: 'Changelog', url: '#', order: 3 },
        ] });
        await prisma.menuItem.create({ data: { menuId: mainMenu.id, title: 'Settings', url: '#', order: 20 } });
        console.log('Seeded default `main` menu with items');
    }
    // Seed the full settings menu used by the admin UI (`settings_main`) — idempotent
    const settingsMenu = await prisma.menu.upsert({
        where: { name: 'settings_main' },
        update: { title: 'Settings Menu', isActive: true },
        create: { name: 'settings_main', title: 'Settings', description: 'Context-aware settings sections for administrators and staff', isActive: true }
    });
    const existingSettingsItems = await prisma.menuItem.findMany({ where: { menuId: settingsMenu.id } });
    if (!existingSettingsItems.length) {
        // Account & Profile
        const accountGroup = await prisma.menuItem.create({ data: { menuId: settingsMenu.id, title: 'Account & Profile', order: 0, isPublished: true, isVisible: true } });
        await prisma.menuItem.createMany({ data: [
            { menuId: settingsMenu.id, parentId: accountGroup.id, title: 'Profile', url: '/settings/account/profile', order: 0, isPublished: true, isVisible: true, meta: { settingsRoute: '/settings/account/profile' } },
            { menuId: settingsMenu.id, parentId: accountGroup.id, title: 'Security', url: '/settings/account/security', order: 1, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: accountGroup.id, title: 'Notifications', url: '/settings/account/notifications', order: 2, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: accountGroup.id, title: 'Connected Apps', url: '/settings/account/connected-apps', order: 3, isPublished: true, isVisible: true },
        ] });

        // Organization
        const orgGroup = await prisma.menuItem.create({ data: { menuId: settingsMenu.id, title: 'Organization', order: 100, isPublished: true, isVisible: true } });
        await prisma.menuItem.createMany({ data: [
            { menuId: settingsMenu.id, parentId: orgGroup.id, title: 'Organization Settings', url: '/settings/organization', order: 0, isPublished: true, isVisible: true, meta: { settingsCategory: 'general', requiresRoles: ['admin', 'system_admin'] } },
            { menuId: settingsMenu.id, parentId: orgGroup.id, title: 'Branding', url: '/settings/organization/branding', order: 1, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: orgGroup.id, title: 'Locations', url: '/settings/organization/locations', order: 2, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: orgGroup.id, title: 'Teams & Departments', url: '/settings/organization/teams', order: 3, isPublished: true, isVisible: true },
        ] });

        // Security & Access
        const securityGroup = await prisma.menuItem.create({ data: { menuId: settingsMenu.id, title: 'Security & Access', order: 200, isPublished: true, isVisible: true } });
        await prisma.menuItem.createMany({ data: [
            { menuId: settingsMenu.id, parentId: securityGroup.id, title: 'Authentication', url: '/settings/security/authentication', order: 0, isPublished: true, isVisible: true, meta: { settingsCategory: 'auth', requiresRoles: ['admin', 'system_admin'] } },
            { menuId: settingsMenu.id, parentId: securityGroup.id, title: 'Session Policies', url: '/settings/security/sessions', order: 1, isPublished: true, isVisible: true, meta: { settingsCategory: 'security', requiresRoles: ['admin', 'system_admin'] } },
            { menuId: settingsMenu.id, parentId: securityGroup.id, title: 'Roles & Permissions', url: '/settings/security/roles', order: 2, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: securityGroup.id, title: 'Audit Logs', url: '/settings/security/audit-logs', order: 3, isPublished: true, isVisible: true },
        ] });

        // Integrations & API
        const integrationsGroup = await prisma.menuItem.create({ data: { menuId: settingsMenu.id, title: 'Integrations & API', order: 300, isPublished: true, isVisible: true } });
        await prisma.menuItem.createMany({ data: [
            { menuId: settingsMenu.id, parentId: integrationsGroup.id, title: 'Integration Catalog', url: '/settings/integrations/catalog', order: 0, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: integrationsGroup.id, title: 'API Access', url: '/settings/integrations/api', order: 1, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: integrationsGroup.id, title: 'Webhooks', url: '/settings/integrations/webhooks', order: 2, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: integrationsGroup.id, title: 'Developer Console', url: '/settings/integrations/dev-console', order: 3, isPublished: true, isVisible: true },
        ] });

        // Billing & Subscription
        const billingGroup = await prisma.menuItem.create({ data: { menuId: settingsMenu.id, title: 'Billing & Subscription', order: 400, isPublished: true, isVisible: true } });
        await prisma.menuItem.createMany({ data: [
            { menuId: settingsMenu.id, parentId: billingGroup.id, title: 'Plan & Usage', url: '/settings/billing/plan', order: 0, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: billingGroup.id, title: 'Invoices', url: '/settings/billing/invoices', order: 1, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: billingGroup.id, title: 'Payment Methods', url: '/settings/billing/payment-methods', order: 2, isPublished: true, isVisible: true },
        ] });

        // Monitoring & Reliability
        const monitoringGroup = await prisma.menuItem.create({ data: { menuId: settingsMenu.id, title: 'Monitoring & Reliability', order: 500, isPublished: true, isVisible: true } });
        await prisma.menuItem.createMany({ data: [
            { menuId: settingsMenu.id, parentId: monitoringGroup.id, title: 'System Health', url: '/settings/monitoring/health', order: 0, isPublished: true, isVisible: true, meta: { settingsCategory: 'monitoring', requiresRoles: ['admin', 'system_admin'] } },
            { menuId: settingsMenu.id, parentId: monitoringGroup.id, title: 'Alerting', url: '/settings/monitoring/alerting', order: 1, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: monitoringGroup.id, title: 'Data Retention', url: '/settings/monitoring/data-retention', order: 2, isPublished: true, isVisible: true },
        ] });

        // Documentation & Support
        const docsGroup = await prisma.menuItem.create({ data: { menuId: settingsMenu.id, title: 'Documentation & Support', order: 600, isPublished: true, isVisible: true } });
        await prisma.menuItem.createMany({ data: [
            { menuId: settingsMenu.id, parentId: docsGroup.id, title: 'Knowledge Base', url: '/settings/docs/knowledge-base', order: 0, isPublished: true, isVisible: true, meta: { settingsCategory: 'docs', requiresRoles: ['admin', 'system_admin'] } },
            { menuId: settingsMenu.id, parentId: docsGroup.id, title: 'Release Notes', url: '/settings/docs/release-notes', order: 1, isPublished: true, isVisible: true },
            { menuId: settingsMenu.id, parentId: docsGroup.id, title: 'Support Center', url: '/settings/docs/support', order: 2, isPublished: true, isVisible: true },
        ] });

        console.log('Seeded full `settings_main` menu with default sections and items');
    }
}
main()
    .catch(e => {
    console.error(e);
    process.exit(1);
})
    .finally(async () => {
    await prisma.$disconnect();
});
