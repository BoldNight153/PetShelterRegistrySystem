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
