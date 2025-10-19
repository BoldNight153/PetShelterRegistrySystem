// Runtime adapter: this file is the runtime boundary and may import runtime-only helpers
// from `frontend/src/lib/api`. UI code should not import types from that module —
// instead use the service interfaces under `services/interfaces`.
import * as api from '../../lib/api';
import type { IAuthService } from '../interfaces/auth.interface';

export class AuthAdapter implements IAuthService {
  async login(input: { email: string; password: string }) {
    return api.login(input);
  }
  async register(input: { email: string; password: string; name?: string }) {
    return api.register(input);
  }
  async logout() {
    return api.logout();
  }
  async refresh() {
    return api.refresh();
  }
}

export default new AuthAdapter();
