import { PrismaClient } from '@prisma/client';
import { IRoleService, RoleRow, PermissionRow } from './interfaces/roleService.interface';

export class RoleService implements IRoleService {
  private prisma: PrismaClient;

  constructor({ prisma }: { prisma: PrismaClient }) {
    this.prisma = prisma;
  }

  async listRoles(): Promise<RoleRow[]> {
    const rows = await this.prisma.role.findMany({ orderBy: { rank: 'desc' } });
    return rows;
  }

  async upsertRole(name: string, rank: number, description?: string | null): Promise<RoleRow> {
    const r = await this.prisma.role.upsert({ where: { name }, update: { rank, description }, create: { name, rank, description } });
    return r;
  }

  async deleteRole(name: string): Promise<void> {
    await this.prisma.role.delete({ where: { name } });
  }

  async listPermissions(): Promise<PermissionRow[]> {
    const rows = await this.prisma.permission.findMany({ orderBy: { name: 'asc' } });
    return rows;
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
    return rp.map(r => r.permission).sort((a, b) => a.name.localeCompare(b.name));
  }
}

export default RoleService;
