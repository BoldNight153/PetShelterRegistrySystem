import type { Role, Permission } from '../../lib/api';

export interface IRoleService {
  listRoles(): Promise<Role[]>;
  upsertRole(input: { name: string; rank?: number; description?: string }): Promise<unknown>;
  deleteRole(name: string): Promise<void>;
  listPermissions(): Promise<Permission[]>;
  listRolePermissions(roleName: string): Promise<Permission[]>;
  grantPermission(roleName: string, permission: string): Promise<unknown>;
  revokePermission(roleName: string, permission: string): Promise<unknown>;
}
