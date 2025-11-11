import { PrismaClient } from '@prisma/client';

type Prisma = PrismaClient;

export async function ensureRole(prisma: Prisma, name: string, rank = 0, description?: string) {
  return await prisma.role.upsert({
    where: { name },
    update: { rank, description },
    create: { name, rank, description },
  });
}

export async function ensurePermission(prisma: Prisma, name: string, description?: string) {
  return await prisma.permission.upsert({
    where: { name },
    update: { description },
    create: { name, description },
  });
}

export async function grantPermissionToRole(prisma: Prisma, roleName: string, permissionName: string) {
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  if (!role) throw new Error(`Role not found: ${roleName}`);
  const perm = await prisma.permission.findUnique({ where: { name: permissionName } });
  if (!perm) throw new Error(`Permission not found: ${permissionName}`);
  return await prisma.rolePermission.upsert({
    where: { roleId_permissionId: { roleId: role.id, permissionId: perm.id } },
    update: {},
    create: { roleId: role.id, permissionId: perm.id },
  });
}

export async function grantPermissionsToRole(prisma: Prisma, roleName: string, permissionNames: string[]) {
  for (const p of permissionNames) {
    await ensurePermission(prisma, p, `${p} permission`);

    await grantPermissionToRole(prisma, roleName, p);
  }
}

export async function assignRoleToUser(prisma: Prisma, userId: string, roleName: string) {
  const role = await prisma.role.findUnique({ where: { name: roleName } });
  if (!role) throw new Error(`Role not found: ${roleName}`);
  return await prisma.userRole.upsert({
    where: { userId_roleId: { userId, roleId: role.id } },
    update: {},
    create: { userId, roleId: role.id },
  });
}

export async function ensureRoleWithPermissionsForUser(
  prisma: Prisma,
  userId: string,
  roleName: string,
  permissions: string[]
) {
  await ensureRole(prisma, roleName, 60, `${roleName} role`);
  if (permissions.length) {
    await grantPermissionsToRole(prisma, roleName, permissions);
  }
  await assignRoleToUser(prisma, userId, roleName);
}
