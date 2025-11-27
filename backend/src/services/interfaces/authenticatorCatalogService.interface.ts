import type { AuthenticatorCatalog, Prisma } from '@prisma/client';

type NullableStringKeys = 'description' | 'issuer' | 'helper' | 'docsUrl';

export type AuthenticatorCatalogInput = {
  id: string;
  label: string;
  factorType: AuthenticatorCatalog['factorType'];
} & {
  [K in NullableStringKeys]?: string | null;
} & {
  tags?: string[] | null;
  metadata?: Prisma.JsonValue | null;
  sortOrder?: number | null;
};

export type AuthenticatorCatalogUpdate = Partial<Omit<AuthenticatorCatalogInput, 'id'>>;

export type AuthenticatorCatalogRecord = AuthenticatorCatalog;

export type AuthenticatorCatalogListOptions = {
  includeArchived?: boolean;
};

export interface IAuthenticatorCatalogService {
  list(options?: AuthenticatorCatalogListOptions): Promise<AuthenticatorCatalogRecord[]>;
  getById(id: string): Promise<AuthenticatorCatalogRecord | null>;
  create(input: AuthenticatorCatalogInput, actorId?: string | null): Promise<AuthenticatorCatalogRecord>;
  update(id: string, input: AuthenticatorCatalogUpdate, actorId?: string | null): Promise<AuthenticatorCatalogRecord>;
  archive(id: string, actorId?: string | null): Promise<void>;
  restore(id: string, actorId?: string | null): Promise<void>;
}

export default IAuthenticatorCatalogService;

