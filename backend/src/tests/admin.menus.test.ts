import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';
import { createLoggedInAdminAgent } from './helpers/agent';

jest.setTimeout(30000);

const ADMIN_MENUS_PATH = '/admin/menus';

describe('Admin menus endpoints', () => {
  const prisma: any = new PrismaClient();
  let agent: request.SuperAgentTest;
  let adminUserId: string | undefined;

  beforeAll(async () => {
    const res = await createLoggedInAdminAgent();
    agent = res.agent;
    adminUserId = res.user.id;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('creates, lists, gets, updates and deletes a menu', async () => {
    const name = `qa_menu_${Date.now()}`;
    // create
    const createRes = await agent.post(ADMIN_MENUS_PATH).send({ name, title: 'QA Menu', isActive: true });
    expect(createRes.status).toBe(200);
    expect(createRes.body).toHaveProperty('id');
    expect(createRes.body.name).toBe(name);
    const menuId = createRes.body.id;

    // audit log created
    const audit = await prisma.auditLog.findFirst({ where: { action: 'admin.menus.create', userId: adminUserId }, orderBy: { createdAt: 'desc' } });
    expect(audit).toBeTruthy();

    // list
    const listRes = await agent.get(ADMIN_MENUS_PATH);
    expect(listRes.status).toBe(200);
    expect(Array.isArray(listRes.body)).toBe(true);
    const found = (listRes.body as any[]).find(m => m.name === name);
    expect(found).toBeTruthy();

    // get by name
    const getRes = await agent.get(`${ADMIN_MENUS_PATH}/${name}`);
    expect(getRes.status).toBe(200);
    expect(getRes.body.name).toBe(name);

    // update
    const updRes = await agent.put(`${ADMIN_MENUS_PATH}/${menuId}`).send({ title: 'Updated QA Menu' });
    expect(updRes.status).toBe(200);
    expect(updRes.body.title).toBe('Updated QA Menu');

    const updAudit = await prisma.auditLog.findFirst({ where: { action: 'admin.menus.update', userId: adminUserId }, orderBy: { createdAt: 'desc' } });
    expect(updAudit).toBeTruthy();

    // delete
    const delRes = await agent.delete(`${ADMIN_MENUS_PATH}/${menuId}`);
    expect(delRes.status).toBe(204);
    const delAudit = await prisma.auditLog.findFirst({ where: { action: 'admin.menus.delete', userId: adminUserId }, orderBy: { createdAt: 'desc' } });
    expect(delAudit).toBeTruthy();
  });

  it('manages menu items and preserves nested tree/order', async () => {
    const name = `qa_menu_items_${Date.now()}`;
    const createRes = await agent.post(ADMIN_MENUS_PATH).send({ name, title: 'QA Items Menu' });
    expect(createRes.status).toBe(200);
    const menuId = createRes.body.id;

    // create root item
    const itemA = await agent.post(`${ADMIN_MENUS_PATH}/${menuId}/items`).send({ title: 'A', order: 2 });
    expect(itemA.status).toBe(200);
    const itemAId = itemA.body.id;

    // create another root item with lower order => should come first
    const itemB = await agent.post(`${ADMIN_MENUS_PATH}/${menuId}/items`).send({ title: 'B', order: 1 });
    expect(itemB.status).toBe(200);
    const itemBId = itemB.body.id;

    // create child under A
    const child = await agent.post(`${ADMIN_MENUS_PATH}/${menuId}/items`).send({ title: 'A-child', parentId: itemAId, order: 0 });
    expect(child.status).toBe(200);

    // list items (nested)
    const itemsRes = await agent.get(`${ADMIN_MENUS_PATH}/${menuId}/items`);
    expect(itemsRes.status).toBe(200);
    const items = itemsRes.body as any[];
    expect(items.length).toBeGreaterThanOrEqual(2);
    // order should be B then A (since B order=1, A order=2)
    expect(items[0].title).toBe('B');
    expect(items[1].title).toBe('A');
    // A should have children array containing A-child
    const aNode = items.find(i => i.id === itemAId);
    expect(aNode).toBeTruthy();
    expect(Array.isArray(aNode.children)).toBe(true);
    expect(aNode.children.some((c: any) => c.title === 'A-child')).toBe(true);

    // update item
    const upd = await agent.put(`${ADMIN_MENUS_PATH}/items/${itemBId}`).send({ title: 'B-updated' });
    expect(upd.status).toBe(200);
    expect(upd.body.title).toBe('B-updated');

    // delete child
    const delChild = await agent.delete(`${ADMIN_MENUS_PATH}/items/${child.body.id}`);
    expect(delChild.status).toBe(204);

    // cleanup: delete menu (cascades items)
    const delMenu = await agent.delete(`${ADMIN_MENUS_PATH}/${menuId}`);
    expect(delMenu.status).toBe(204);
  });

  it('enforces RBAC (403 for non-admin)', async () => {
    // create a plain user agent
    const anon = request.agent(app);
    const csrfRes = await anon.get('/auth/csrf');
    const token = csrfRes.body?.csrfToken;
    const email = `plain.${Date.now()}@example.test`;
    const password = 'P@ssw0rd!';
    await anon.post('/auth/register').set('x-csrf-token', String(token)).send({ email, password, name: 'Plain User' });
    // attempt admin action
    const res = await anon.post(ADMIN_MENUS_PATH).send({ name: `nope_${Date.now()}`, title: 'Should fail' });
    expect(res.status === 401 || res.status === 403).toBe(true);
  });

  it('returns 400 for invalid payloads and 404 for missing resources', async () => {
    // missing required name for menu creation
    const badCreate = await agent.post(ADMIN_MENUS_PATH).send({ title: 'no name' });
    expect(badCreate.status).toBe(400);

    // create a menu to test item validation and 404 cases
    const ok = await agent.post(ADMIN_MENUS_PATH).send({ name: `qa_temp_${Date.now()}`, title: 'temp' });
    expect(ok.status).toBe(200);
    const menuId = ok.body.id;

    // invalid menu item payload
    const badItem = await agent.post(`${ADMIN_MENUS_PATH}/${menuId}/items`).send({});
    expect(badItem.status).toBe(400);

    // update non-existent menu
    const updMissing = await agent.put(`${ADMIN_MENUS_PATH}/no-such-id`).send({ title: 'x' });
    expect(updMissing.status).toBe(404);

    // delete non-existent menu
    const delMissing = await agent.delete(`${ADMIN_MENUS_PATH}/no-such-id`);
    expect(delMissing.status).toBe(404);

    // update non-existent item
    const updItemMissing = await agent.put(`${ADMIN_MENUS_PATH}/items/no-such-id`).send({ title: 'x' });
    expect(updItemMissing.status).toBe(404);

    // delete non-existent item
    const delItemMissing = await agent.delete(`${ADMIN_MENUS_PATH}/items/no-such-id`);
    expect(delItemMissing.status).toBe(404);

    // cleanup
    await agent.delete(`${ADMIN_MENUS_PATH}/${menuId}`);
  });
});
