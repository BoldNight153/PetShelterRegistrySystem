// Runtime adapter: this file is the runtime boundary and may import runtime-only helpers
// from `frontend/src/lib/api`. UI code should not import types from that module —
// instead use the service interfaces under `services/interfaces`.
import * as api from '../../lib/api';
import type { IRoleService } from '../interfaces/role.interface';

export class RoleAdapter implements IRoleService {
  listRoles() { return api.listRoles(); }
  upsertRole(input: { name: string; rank?: number; description?: string }) { return api.upsertRole(input); }
  deleteRole(name: string) { return api.deleteRole(name); }
  listPermissions() { return api.listPermissions(); }
  listRolePermissions(roleName: string) { return api.listRolePermissions(roleName); }
  grantPermission(roleName: string, permission: string) { return api.grantPermission(roleName, permission); }
  revokePermission(roleName: string, permission: string) { return api.revokePermission(roleName, permission); }
}

export default new RoleAdapter();
