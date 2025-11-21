export type LoginChallengeFactorType = 'totp' | 'sms' | 'push' | 'hardware_key' | 'backup_codes';

export type LoginChallengeFactor = {
  id: string;
  type: LoginChallengeFactorType;
  label: string;
  lastUsedAt?: string | null;
};

export type LoginChallengeDevice = {
  fingerprint?: string | null;
  label?: string | null;
  platform?: string | null;
  trustRequested: boolean;
  trusted: boolean;
  allowTrust: boolean;
};

export type LoginChallengePayload = {
  id: string;
  expiresAt: string;
  reason: 'mfa_required' | 'untrusted_device';
  factors: LoginChallengeFactor[];
  defaultFactorId: string | null;
  device: LoginChallengeDevice;
};

export type LoginChallengeResponse = {
  challengeRequired: true;
  challenge: LoginChallengePayload;
};

export type AuthenticatedUser = {
  id: string;
  email: string;
  name?: string | null;
  emailVerified?: boolean | null;
  lastLoginAt?: string | null;
  [key: string]: unknown;
};

export type AuthLoginResult = LoginChallengeResponse | AuthenticatedUser | null;

export type LoginDeviceMetadata = {
  deviceFingerprint?: string;
  deviceName?: string;
  devicePlatform?: string;
  devicePushToken?: string;
  trustThisDevice?: boolean;
};

export type LoginRequestInput = {
  email: string;
  password: string;
} & LoginDeviceMetadata;

export type VerifyMfaChallengeInput = {
  challengeId: string;
  code?: string;
  backupCode?: string;
  factorId?: string;
  method?: 'totp' | 'backup_code';
} & LoginDeviceMetadata;

export function isLoginChallengeResponse(value: unknown): value is LoginChallengeResponse {
  return Boolean(
    value &&
    typeof value === 'object' &&
    'challengeRequired' in value &&
    (value as Record<string, unknown>).challengeRequired === true &&
    'challenge' in value
  );
}

export function isAuthenticatedUser(value: unknown): value is AuthenticatedUser {
  return Boolean(value && typeof value === 'object' && 'id' in value);
}
