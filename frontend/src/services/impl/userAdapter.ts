import * as api from '../../lib/api';
import type { IUserService } from '../interfaces/user.interface';

export class UserAdapter implements IUserService {
  searchUsers(q?: string, page?: number, pageSize?: number) {
    return api.searchUsers(q, page, pageSize);
  }
  getUser(userId: string) {
    return api.getUser(userId);
  }
  assignUserRole(userId: string, roleName: string) {
    return api.assignUserRole(userId, roleName);
  }
  revokeUserRole(userId: string, roleName: string) {
    return api.revokeUserRole(userId, roleName);
  }
  lockUser(userId: string, reason: string, expiresAt?: string | null, notes?: string) {
    return api.lockUser(userId, reason, expiresAt, notes);
  }
  unlockUser(userId: string, unlockReason?: string) {
    return api.unlockUser(userId, unlockReason);
  }
  listSessions(userId: string) {
    return api.listUserSessions(userId);
  }
}

export default new UserAdapter();
