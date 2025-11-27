export type AuthenticatorFieldOption = {
  label: string;
  value: string;
};

export type AuthenticatorFieldSeed = {
  key: string;
  label: string;
  type: 'text' | 'textarea' | 'url' | 'select';
  required?: boolean;
  helper?: string;
  placeholder?: string;
  defaultValue?: string;
  order?: number;
  options?: AuthenticatorFieldOption[];
};

export type AuthenticatorCatalogSeed = {
  id: string;
  label: string;
  description?: string;
  factorType: 'TOTP' | 'SMS' | 'PUSH' | 'HARDWARE_KEY' | 'BACKUP_CODES';
  issuer?: string;
  helper?: string;
  docsUrl?: string;
  tags?: string[];
  metadata?: Record<string, unknown> | null;
  sortOrder?: number;
  fields?: AuthenticatorFieldSeed[];
};

export const DEFAULT_TOTP_ISSUER = 'Pet Shelter Registry';
const ISSUER_FIELD_LABEL = 'Issuer label';
const ACCOUNT_NAME_FIELD_LABEL = 'Account name format';

const STANDARD_TOTP_FIELDS: AuthenticatorFieldSeed[] = [
  {
    key: 'issuer',
    label: ISSUER_FIELD_LABEL,
    type: 'text',
    required: true,
    helper: 'Displayed on generated QR codes and inside authenticator apps.',
    placeholder: DEFAULT_TOTP_ISSUER,
    defaultValue: DEFAULT_TOTP_ISSUER,
    order: 10,
  },
  {
    key: 'accountName',
    label: ACCOUNT_NAME_FIELD_LABEL,
    type: 'text',
    required: true,
    helper: 'Usually the user email. Supports tokens such as {email} or {name}.',
    placeholder: '{email}',
    defaultValue: '{email}',
    order: 20,
  },
];

const PASSWORD_MANAGER_TOTP_FIELDS: AuthenticatorFieldSeed[] = [
  {
    key: 'issuer',
    label: 'Vault issuer',
    type: 'text',
    required: true,
    helper: 'Used as the entry title inside password managers.',
    placeholder: DEFAULT_TOTP_ISSUER,
    defaultValue: DEFAULT_TOTP_ISSUER,
    order: 10,
  },
  {
    key: 'accountName',
    label: ACCOUNT_NAME_FIELD_LABEL,
    type: 'text',
    required: true,
    helper: 'Defaults to the user email. Supports {email} or {name} tokens.',
    placeholder: '{email}',
    defaultValue: '{email}',
    order: 20,
  },
];

const cloneFields = (fields: AuthenticatorFieldSeed[] | undefined): AuthenticatorFieldSeed[] | undefined => {
  if (!fields) return undefined;
  return fields.map(field => ({
    ...field,
    options: field.options ? field.options.map(option => ({ ...option })) : undefined,
  }));
};

export const DEFAULT_AUTHENTICATOR_CATALOG: AuthenticatorCatalogSeed[] = [
  {
    id: 'google',
    label: 'Google Authenticator',
    description: 'Android + iOS code generator',
    factorType: 'TOTP',
    issuer: DEFAULT_TOTP_ISSUER,
    tags: ['mobile', 'offline'],
    sortOrder: 10,
    fields: cloneFields(STANDARD_TOTP_FIELDS),
  },
  {
    id: 'microsoft',
    label: 'Microsoft Authenticator',
    description: 'Microsoft Entra + push approvals',
    factorType: 'TOTP',
    issuer: DEFAULT_TOTP_ISSUER,
    tags: ['push', 'enterprise'],
    sortOrder: 20,
    fields: cloneFields(STANDARD_TOTP_FIELDS),
  },
  {
    id: 'authy',
    label: 'Authy',
    description: 'Desktop + mobile authenticator with multi-device sync',
    factorType: 'TOTP',
    issuer: DEFAULT_TOTP_ISSUER,
    tags: ['desktop', 'sync'],
    sortOrder: 30,
    fields: cloneFields(STANDARD_TOTP_FIELDS),
  },
  {
    id: '1password',
    label: '1Password',
    description: 'Built-in OTP field stored with your vault',
    factorType: 'TOTP',
    issuer: DEFAULT_TOTP_ISSUER,
    tags: ['password-manager'],
    sortOrder: 40,
    fields: cloneFields(PASSWORD_MANAGER_TOTP_FIELDS),
  },
  {
    id: 'okta',
    label: 'Okta Verify',
    description: 'Push approvals plus classic OTP codes',
    factorType: 'TOTP',
    issuer: DEFAULT_TOTP_ISSUER,
    tags: ['push', 'enterprise'],
    sortOrder: 50,
    fields: cloneFields(STANDARD_TOTP_FIELDS),
  },
  {
    id: 'webauthn_keys',
    label: 'Hardware security keys',
    description: 'FIDO2 / WebAuthn keys such as YubiKey or SoloKey',
    factorType: 'HARDWARE_KEY',
    helper: 'Phishing-resistant, requires browser support for WebAuthn.',
    tags: ['phishing-resistant'],
    sortOrder: 60,
  },
  {
    id: 'platform_passkeys',
    label: 'Passkeys (platform authenticators)',
    description: 'macOS Touch ID, Windows Hello, and Android passkeys',
    factorType: 'HARDWARE_KEY',
    helper: 'Stored on user devices with optional sync via cloud accounts.',
    tags: ['passkey'],
    sortOrder: 70,
  },
  {
    id: 'sms_backup',
    label: 'SMS fallback codes',
    description: 'One-time codes texted to verified phone numbers',
    factorType: 'SMS',
    helper: 'Use sparingly; susceptible to SIM swap attacks.',
    tags: ['fallback'],
    sortOrder: 80,
  },
  {
    id: 'push_trusted',
    label: 'Push approvals',
    description: 'In-app push prompts via trusted mobile apps',
    factorType: 'PUSH',
    helper: 'Pairs best with device biometrics and anomaly detection.',
    tags: ['push'],
    sortOrder: 90,
  },
  {
    id: 'backup_codes',
    label: 'One-time backup codes',
    description: 'Printable codes stored offline for emergencies',
    factorType: 'BACKUP_CODES',
    helper: 'Regenerate after each download to invalidate old copies.',
    tags: ['break-glass'],
    sortOrder: 100,
  },
];

export const DEFAULT_ENABLED_AUTHENTICATOR_IDS = ['google', 'microsoft', 'authy', '1password', 'okta'];
