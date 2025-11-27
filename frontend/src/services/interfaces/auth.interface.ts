import type { UserProfileUpdateInput } from './types';
import type { AuthLoginResult, LoginRequestInput, VerifyMfaChallengeInput } from '@/types/auth';

export interface IAuthService {
  login(input: LoginRequestInput): Promise<AuthLoginResult>;
  verifyMfaChallenge(input: VerifyMfaChallengeInput): Promise<any>;
  register(input: { email: string; password: string; name?: string }): Promise<any>;
  logout(): Promise<void>;
  refresh(): Promise<any | null>;
  /**
   * Retrieve the current authenticated user (or null if not authenticated).
   * This encapsulates the runtime '/auth/me' call so callers don't use fetch directly.
   */
  me(): Promise<any | null>;
  updateProfile(input: UserProfileUpdateInput): Promise<any>;
}
