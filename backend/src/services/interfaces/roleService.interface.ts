export interface RoleRow {
  id: string;
  name: string;
  rank: number;
  description?: string | null;
}

export interface PermissionRow {
  id: string;
  name: string;
  description?: string | null;
}

export interface IRoleService {
  listRoles(): Promise<RoleRow[]>;
  upsertRole(name: string, rank: number, description?: string | null): Promise<RoleRow>;
  deleteRole(name: string): Promise<void>;
  listPermissions(): Promise<PermissionRow[]>;
  grantPermissionToRole(roleName: string, permission: string): Promise<void>;
  revokePermissionFromRole(roleName: string, permission: string): Promise<void>;
  listRolePermissions(roleName: string): Promise<PermissionRow[]>;
}

export default IRoleService;
