import { authenticator } from 'otplib';
import QRCode from 'qrcode';

const DEFAULT_ISSUER = 'Pet Shelter Registry System';

authenticator.options = {
  step: 30,
  digits: 6,
  window: 1,
};

export type TotpEnrollmentOptions = {
  secret?: string
  accountName?: string
  issuer?: string
};

export function generateTotpSecret(length = 32): string {
  return authenticator.generateSecret(length);
}

export function buildTotpUri(secret: string, options: TotpEnrollmentOptions = {}): string {
  const issuer = options.issuer?.trim() || DEFAULT_ISSUER;
  const accountName = options.accountName?.trim() || 'Account';
  return authenticator.keyuri(accountName, issuer, secret);
}

export async function buildTotpQrCode(uri: string): Promise<string> {
  return QRCode.toDataURL(uri, { width: 256, margin: 1 });
}

export function verifyTotpCode(secret: string, code: string): boolean {
  const sanitized = String(code ?? '').trim();
  if (!sanitized) return false;
  return authenticator.check(sanitized, secret);
}
