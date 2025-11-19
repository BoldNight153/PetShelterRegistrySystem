/*
  compare_seed_db.js
  Small utility to compare the settings_main menu defined in seed.js with the current DB.

  Usage: node compare_seed_db.js
  It expects that you've set up your DATABASE_URL and run `npx prisma generate` so @prisma/client is available.
*/

const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

async function buildExpected() {
  // Minimal representation matching the seed structure (title and url/parentTitle) used to compare
  return [
    { title: 'Account & Profile', url: null },
    { title: 'Profile', url: '/settings/account/profile', parent: 'Account & Profile' },
    { title: 'Security', url: '/settings/account/security', parent: 'Account & Profile' },
    { title: 'Notifications', url: '/settings/account/notifications', parent: 'Account & Profile' },
    { title: 'Connected Apps', url: '/settings/account/connected-apps', parent: 'Account & Profile' },

    { title: 'Organization', url: null },
    { title: 'Organization Settings', url: '/settings/organization', parent: 'Organization' },
    { title: 'Branding', url: '/settings/organization/branding', parent: 'Organization' },
    { title: 'Locations', url: '/settings/organization/locations', parent: 'Organization' },
    { title: 'Teams & Departments', url: '/settings/organization/teams', parent: 'Organization' },

    { title: 'Security & Access', url: null },
    { title: 'Authentication', url: '/settings/security/authentication', parent: 'Security & Access' },
    { title: 'Session Policies', url: '/settings/security/sessions', parent: 'Security & Access' },
    { title: 'Roles & Permissions', url: '/settings/security/roles', parent: 'Security & Access' },
    { title: 'Audit Logs', url: '/settings/security/audit-logs', parent: 'Security & Access' },

    { title: 'Integrations & API', url: null },
    { title: 'Integration Catalog', url: '/settings/integrations/catalog', parent: 'Integrations & API' },
    { title: 'API Access', url: '/settings/integrations/api', parent: 'Integrations & API' },
    { title: 'Webhooks', url: '/settings/integrations/webhooks', parent: 'Integrations & API' },
    { title: 'Developer Console', url: '/settings/integrations/dev-console', parent: 'Integrations & API' },

    { title: 'Billing & Subscription', url: null },
    { title: 'Plan & Usage', url: '/settings/billing/plan', parent: 'Billing & Subscription' },
    { title: 'Invoices', url: '/settings/billing/invoices', parent: 'Billing & Subscription' },
    { title: 'Payment Methods', url: '/settings/billing/payment-methods', parent: 'Billing & Subscription' },

    { title: 'Monitoring & Reliability', url: null },
    { title: 'System Health', url: '/settings/monitoring/health', parent: 'Monitoring & Reliability' },
    { title: 'Alerting', url: '/settings/monitoring/alerting', parent: 'Monitoring & Reliability' },
    { title: 'Data Retention', url: '/settings/monitoring/data-retention', parent: 'Monitoring & Reliability' },

    { title: 'Documentation & Support', url: null },
    { title: 'Knowledge Base', url: '/settings/docs/knowledge-base', parent: 'Documentation & Support' },
    { title: 'Release Notes', url: '/settings/docs/release-notes', parent: 'Documentation & Support' },
    { title: 'Support Center', url: '/settings/docs/support', parent: 'Documentation & Support' },
  ];
}

async function run() {
  try {
    const expected = await buildExpected();

    const menu = await prisma.menu.findUnique({ where: { name: 'settings_main' } });
    if (!menu) {
      console.log('Menu `settings_main` not found in DB.');
      process.exit(0);
    }

    const items = await prisma.menuItem.findMany({ where: { menuId: menu.id }, include: { parent: true } });

    // Build normalized list from DB
    const normalized = items.map(i => ({ title: i.title, url: i.url || null, parent: i.parent ? i.parent.title : null }));

    // Helper to compare
    function findInList(list, entry) {
      return list.find(l => l.title === entry.title && (l.url || null) === (entry.url || null) && (l.parent || null) === (entry.parent || null));
    }

    const missing = expected.filter(e => !findInList(normalized, e));
    const extra = normalized.filter(n => !findInList(expected, n));

    console.log('\nComparison report for `settings_main`');
    console.log('-----------------------------------');
    console.log('Expected items total:', expected.length);
    console.log('DB items total:', normalized.length);

    if (missing.length) {
      console.log('\nMissing items (present in seed, absent in DB):');
      missing.forEach(m => console.log(` - ${m.parent ? m.parent + ' > ' : ''}${m.title}${m.url ? ' (' + m.url + ')' : ''}`));
    } else {
      console.log('\nNo missing items.');
    }

    if (extra.length) {
      console.log('\nExtra items (present in DB, not in seed):');
      extra.forEach(e => console.log(` - ${e.parent ? e.parent + ' > ' : ''}${e.title}${e.url ? ' (' + e.url + ')' : ''}`));
    } else {
      console.log('\nNo extra items.');
    }

    process.exit(0);
  } catch (err) {
    console.error('Error comparing seed and DB:', err);
    process.exit(2);
  } finally {
    await prisma.$disconnect();
  }
}

run();
