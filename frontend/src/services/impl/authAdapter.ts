// Runtime adapter: this file is the runtime boundary and may import runtime-only helpers
// from `frontend/src/lib/api`. UI code should not import types from that module —
// instead use the service interfaces under `services/interfaces`.
import * as api from '../../lib/api';
import type { IAuthService } from '../interfaces/auth.interface';
import type { UserProfileUpdateInput } from '../interfaces/types';
import type { AuthLoginResult, LoginRequestInput, VerifyMfaChallengeInput } from '@/types/auth';
import { isLoginChallengeResponse } from '@/types/auth';

export class AuthAdapter implements IAuthService {
  async login(input: LoginRequestInput): Promise<AuthLoginResult> {
    const basic = await api.login(input);
    if (isLoginChallengeResponse(basic)) {
      return basic;
    }
    try {
      const detailed = await api.me();
      return detailed ?? basic;
    } catch {
      return basic;
    }
  }

  async verifyMfaChallenge(input: VerifyMfaChallengeInput) {
    const basic = await api.verifyMfaChallenge(input);
    try {
      const detailed = await api.me();
      return detailed ?? basic;
    } catch {
      return basic;
    }
  }
  async register(input: { email: string; password: string; name?: string }) {
    const basic = await api.register(input);
    try {
      const detailed = await api.me();
      return detailed ?? basic;
    } catch {
      return basic;
    }
  }
  async logout() {
    return api.logout();
  }
  async refresh() {
    try {
      const refreshed = await api.refresh();
      if (!refreshed) return null;
      return await api.me();
    } catch {
      return null;
    }
  }
  async me() {
    return api.me();
  }
  async updateProfile(input: UserProfileUpdateInput) {
    return api.updateProfile(input);
  }
}

export default new AuthAdapter();
