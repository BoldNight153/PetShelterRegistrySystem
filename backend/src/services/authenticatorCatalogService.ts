import { Prisma, PrismaClient } from '@prisma/client';
import type {
  IAuthenticatorCatalogService,
  AuthenticatorCatalogInput,
  AuthenticatorCatalogUpdate,
  AuthenticatorCatalogListOptions,
} from './interfaces/authenticatorCatalogService.interface';

const LEGACY_FACTOR_TYPES = ['totp', 'sms', 'push', 'hardware_key', 'backup_codes'] as const;

const normalizeLegacyFactorTypes = async (prisma: PrismaClient) => {
  try {
    await prisma.$executeRawUnsafe(
      `UPDATE "AuthenticatorCatalog"
       SET "factorType" = UPPER("factorType")
       WHERE LOWER("factorType") IN (${LEGACY_FACTOR_TYPES.map(value => `'${value}'`).join(', ')})`,
    );
  } catch {
    // Best-effort data cleanup; ignore failures so callers can proceed.
  }
};

const toNullableJsonInput = (
  value: Prisma.JsonValue | string[] | null | undefined,
): Prisma.InputJsonValue | Prisma.NullableJsonNullValueInput | undefined => {
  if (typeof value === 'undefined') return undefined;
  if (value === null) return Prisma.JsonNull;
  return value as Prisma.InputJsonValue;
};

const toOptionalSortOrder = (value?: number | null) => (typeof value === 'number' ? value : undefined);
const normalizeOptionalString = (value: string | null | undefined): string | null | undefined => {
  if (typeof value === 'undefined') return undefined;
  if (value === null) return null;
  const trimmed = value.trim();
  return trimmed.length === 0 ? null : trimmed;
};

export class AuthenticatorCatalogService implements IAuthenticatorCatalogService {
  private prisma: PrismaClient;
  private hasNormalizedFactors = false;

  constructor({ prisma }: { prisma: PrismaClient }) {
    this.prisma = prisma;
  }

  list(options?: AuthenticatorCatalogListOptions) {
    const includeArchived = Boolean(options?.includeArchived);
    return (async () => {
      if (!this.hasNormalizedFactors) {
        await normalizeLegacyFactorTypes(this.prisma);
        this.hasNormalizedFactors = true;
      }
      return this.prisma.authenticatorCatalog.findMany({
        where: includeArchived ? {} : { isArchived: false },
        orderBy: { sortOrder: 'asc' },
      });
    })();
  }

  getById(id: string) {
    return this.prisma.authenticatorCatalog.findUnique({ where: { id } });
  }

  create(input: AuthenticatorCatalogInput, actorId?: string | null) {
    return this.prisma.authenticatorCatalog.create({
      data: {
        id: input.id,
        label: input.label,
        description: normalizeOptionalString(input.description) ?? null,
        factorType: input.factorType,
        issuer: normalizeOptionalString(input.issuer) ?? null,
        helper: normalizeOptionalString(input.helper) ?? null,
        docsUrl: normalizeOptionalString(input.docsUrl) ?? null,
        tags: toNullableJsonInput(input.tags ?? null),
        metadata: toNullableJsonInput(input.metadata ?? null),
        sortOrder: typeof input.sortOrder === 'number' ? input.sortOrder : 0,
        createdBy: actorId ?? null,
        updatedBy: actorId ?? null,
        isSystem: false,
      },
    });
  }

  update(id: string, input: AuthenticatorCatalogUpdate, actorId?: string | null) {
    return this.prisma.authenticatorCatalog.update({
      where: { id },
      data: {
        label: input.label ?? undefined,
        description: normalizeOptionalString(input.description),
        factorType: input.factorType ?? undefined,
        issuer: normalizeOptionalString(input.issuer),
        helper: normalizeOptionalString(input.helper),
        docsUrl: normalizeOptionalString(input.docsUrl),
        tags: toNullableJsonInput(input.tags),
        metadata: typeof input.metadata === 'undefined' ? undefined : toNullableJsonInput(input.metadata ?? null),
        sortOrder: toOptionalSortOrder(input.sortOrder),
        updatedBy: actorId ?? undefined,
      },
    });
  }

  async archive(id: string, actorId?: string | null) {
    const authenticator = await this.prisma.authenticatorCatalog.findUnique({ where: { id } });
    if (!authenticator) {
      throw new Error('Authenticator not found');
    }
    if (authenticator.isSystem) {
      throw new Error('System authenticators cannot be archived');
    }
    await this.prisma.authenticatorCatalog.update({
      where: { id },
      data: {
        isArchived: true,
        archivedAt: new Date(),
        archivedBy: actorId ?? null,
      },
    });
  }

  async restore(id: string, actorId?: string | null) {
    await this.prisma.authenticatorCatalog.update({
      where: { id },
      data: {
        isArchived: false,
        archivedAt: null,
        archivedBy: null,
        updatedBy: actorId ?? undefined,
      },
    });
  }
}

export default AuthenticatorCatalogService;
