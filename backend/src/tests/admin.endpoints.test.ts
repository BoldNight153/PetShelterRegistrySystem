import request from 'supertest';
import app from '../index';
import { PrismaClient } from '@prisma/client';
import { ensureRoleWithPermissionsForUser, ensureRole, ensurePermission, grantPermissionToRole } from './helpers/rbac';
import { createLoggedInAdminAgent } from './helpers/agent';

describe('Admin endpoints', () => {
  const prisma: any = new PrismaClient();
  const agent = request.agent(app);
  let csrfToken: string | undefined;
  let adminEmail: string | undefined;
  let adminUserId: string | undefined;

  beforeAll(async () => {
    const { agent: a, user, email } = await createLoggedInAdminAgent();
    // rebind the local agent reference by copying cookies via supertest.agent reuse
    (agent as any).jar = (a as any).jar;
    adminEmail = email;
    adminUserId = user.id;
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('lists roles and permissions', async () => {
    const rolesRes = await agent.get('/admin/roles');
    expect(rolesRes.status).toBe(200);
    expect(Array.isArray(rolesRes.body)).toBe(true);
    const permsRes = await agent.get('/admin/permissions');
    expect(permsRes.status).toBe(200);
    expect(Array.isArray(permsRes.body)).toBe(true);
  });

  it('upserts and deletes a role, auditing actions', async () => {
    const roleName = `qa_role_${Date.now()}`;
    const upsertRes = await agent.post('/admin/roles/upsert').send({ name: roleName, rank: 10, description: 'QA role' });
    expect(upsertRes.status).toBe(200);
    expect(upsertRes.body.name).toBe(roleName);

    // Check audit log for upsert
    const upsertAudit = await prisma.auditLog.findFirst({
      where: { action: 'admin.roles.upsert', userId: adminUserId },
      orderBy: { createdAt: 'desc' },
    });
    expect(upsertAudit).toBeTruthy();

    const delRes = await agent.delete(`/admin/roles/${roleName}`);
    expect(delRes.status).toBe(204);

    // Check audit log for delete
    const deleteAudit = await prisma.auditLog.findFirst({
      where: { action: 'admin.roles.delete', userId: adminUserId },
      orderBy: { createdAt: 'desc' },
    });
    expect(deleteAudit).toBeTruthy();
  });

  it('grants and revokes permissions to a role with audit logging', async () => {
    const roleName = `perm_role_${Date.now()}`;
    await ensureRole(prisma, roleName, 5, 'Temporary role');
    const permName = `perm.${Date.now()}.write`;
    await ensurePermission(prisma, permName, 'Temporary permission');

    const grantRes = await agent.post('/admin/permissions/grant').send({ roleName, permission: permName });
    expect(grantRes.status).toBe(200);
    expect(grantRes.body.ok).toBe(true);

    const grantAudit = await prisma.auditLog.findFirst({
      where: { action: 'admin.permissions.grant', userId: adminUserId },
      orderBy: { createdAt: 'desc' },
    });
    expect(grantAudit).toBeTruthy();

    // verify rolePermission exists
    const role = await prisma.role.findUnique({ where: { name: roleName } });
    const perm = await prisma.permission.findUnique({ where: { name: permName } });
    const rp = await prisma.rolePermission.findFirst({ where: { roleId: role?.id, permissionId: perm?.id } });
    expect(rp).toBeTruthy();

    const revokeRes = await agent.post('/admin/permissions/revoke').send({ roleName, permission: permName });
    expect(revokeRes.status).toBe(200);
    expect(revokeRes.body.ok).toBe(true);

    const revokeAudit = await prisma.auditLog.findFirst({
      where: { action: 'admin.permissions.revoke', userId: adminUserId },
      orderBy: { createdAt: 'desc' },
    });
    expect(revokeAudit).toBeTruthy();
  });

  it('assigns and revokes a role from a user with audit logging', async () => {
    // create a plain user
    const agent2 = request.agent(app);
    const csrfRes = await agent2.get('/auth/csrf');
    const token = csrfRes.body?.csrfToken;
    const email = `user.${Date.now()}@example.test`;
    const password = 'P@ssw0rd!';
    await agent2
      .post('/auth/register')
      .set('x-csrf-token', String(token))
      .send({ email, password });
    const user = await prisma.user.findUnique({ where: { email } });
    expect(user).toBeTruthy();

    const roleName = `assignable_role_${Date.now()}`;
    await ensureRole(prisma, roleName, 1, 'Assignable role');

    const assignRes = await agent.post('/admin/users/assign-role').send({ userId: user!.id, roleName });
    expect(assignRes.status).toBe(200);

    const assignAudit = await prisma.auditLog.findFirst({
      where: { action: 'admin.users.assign_role', userId: adminUserId },
      orderBy: { createdAt: 'desc' },
    });
    expect(assignAudit).toBeTruthy();

    // verify mapping exists
    const ur = await prisma.userRole.findFirst({ where: { userId: user!.id } });
    expect(ur).toBeTruthy();

    const revokeRes = await agent.post('/admin/users/revoke-role').send({ userId: user!.id, roleName });
    expect(revokeRes.status).toBe(200);
    expect(revokeRes.body.ok).toBe(true);

    const revokeAudit = await prisma.auditLog.findFirst({
      where: { action: 'admin.users.revoke_role', userId: adminUserId },
      orderBy: { createdAt: 'desc' },
    });
    expect(revokeAudit).toBeTruthy();
  });

  it('returns 404 for granting permission to non-existent role or permission', async () => {
    const res1 = await agent.post('/admin/permissions/grant').send({ roleName: 'no_such_role', permission: 'no.perm' });
    expect(res1.status).toBe(404);
    const res2 = await agent.post('/admin/permissions/revoke').send({ roleName: 'no_such_role', permission: 'no.perm' });
    expect(res2.status).toBe(404);
  });

  it('returns 404 when deleting a non-existent role', async () => {
    const res = await agent.delete(`/admin/roles/no_such_role_${Date.now()}`);
    expect(res.status).toBe(404);
  });

  it('returns 400 for invalid payloads on upsert/grant/revoke/assign/revoke', async () => {
    // missing name
    const r1 = await agent.post('/admin/roles/upsert').send({ rank: 1 });
    expect(r1.status).toBe(400);
    // invalid types
    const r2 = await agent.post('/admin/roles/upsert').send({ name: '', rank: -1 });
    expect(r2.status).toBe(400);
    const g1 = await agent.post('/admin/permissions/grant').send({ roleName: '', permission: '' });
    expect(g1.status).toBe(400);
    const rv1 = await agent.post('/admin/permissions/revoke').send({});
    expect(rv1.status).toBe(400);
    const a1 = await agent.post('/admin/users/assign-role').send({ userId: '', roleName: '' });
    expect(a1.status).toBe(400);
    const a2 = await agent.post('/admin/users/revoke-role').send({});
    expect(a2.status).toBe(400);
  });
});
