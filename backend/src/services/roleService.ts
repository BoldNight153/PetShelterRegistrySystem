import { PrismaClient } from '@prisma/client';
import { IRoleService, RoleRow, PermissionRow } from './interfaces/roleService.interface';

export class RoleService implements IRoleService {
  private prisma: PrismaClient;

  constructor({ prisma }: { prisma: PrismaClient }) {
    this.prisma = prisma;
  }

  async listRoles(): Promise<RoleRow[]> {
    return this.prisma.role.findMany({ orderBy: { rank: 'desc' } }) as Promise<RoleRow[]>;
  }

  async upsertRole(name: string, rank: number, description?: string | null): Promise<RoleRow> {
    return this.prisma.role.upsert({ where: { name }, update: { rank, description }, create: { name, rank, description } }) as Promise<RoleRow>;
  }

  async deleteRole(name: string): Promise<void> {
    await this.prisma.role.delete({ where: { name } });
  }

  async listPermissions(): Promise<PermissionRow[]> {
    return this.prisma.permission.findMany({ orderBy: { name: 'asc' } }) as Promise<PermissionRow[]>;
  }

  async grantPermissionToRole(roleName: string, permission: string): Promise<void> {
    const role = await this.prisma.role.findUnique({ where: { name: roleName } });
    const perm = await this.prisma.permission.findUnique({ where: { name: permission } });
    if (!role || !perm) throw new Error('role or permission not found');
    await this.prisma.rolePermission.upsert({
      where: { roleId_permissionId: { roleId: role.id, permissionId: perm.id } as any },
      update: {},
      create: { roleId: role.id, permissionId: perm.id },
    });
  }

  async revokePermissionFromRole(roleName: string, permission: string): Promise<void> {
    const role = await this.prisma.role.findUnique({ where: { name: roleName } });
    const perm = await this.prisma.permission.findUnique({ where: { name: permission } });
    if (!role || !perm) throw new Error('role or permission not found');
    await this.prisma.rolePermission.delete({ where: { roleId_permissionId: { roleId: role.id, permissionId: perm.id } as any } });
  }

  async listRolePermissions(roleName: string): Promise<PermissionRow[]> {
    const role = await this.prisma.role.findUnique({ where: { name: roleName } });
    if (!role) return [];
    const rp = await this.prisma.rolePermission.findMany({ where: { roleId: role.id }, include: { permission: true } });
    return (rp as any[]).map(r => r.permission).sort((a, b) => a.name.localeCompare(b.name));
  }
}

export default RoleService;
