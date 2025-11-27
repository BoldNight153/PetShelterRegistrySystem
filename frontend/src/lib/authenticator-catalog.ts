import {
  DEFAULT_AUTHENTICATOR_CATALOG,
  DEFAULT_ENABLED_AUTHENTICATOR_IDS,
  DEFAULT_TOTP_ISSUER,
  type AuthenticatorCatalogSeed,
} from '@petshelter/authenticator-catalog'

export type AuthenticatorCatalogEntry = AuthenticatorCatalogSeed & { description: string }

export const AUTHENTICATOR_CATALOG = DEFAULT_AUTHENTICATOR_CATALOG
export const DEFAULT_ENABLED_AUTHENTICATORS = DEFAULT_ENABLED_AUTHENTICATOR_IDS
export { DEFAULT_TOTP_ISSUER }

export function findAuthenticatorById(id: string | null | undefined): AuthenticatorCatalogEntry | undefined {
  if (!id) return undefined
  return AUTHENTICATOR_CATALOG.find((entry) => entry.id === id)
}

