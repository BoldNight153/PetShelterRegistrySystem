import { PrismaClient } from '@prisma/client';
import type { Prisma } from '@prisma/client';
import type {
  IAuditService,
  AuditListParams,
  AuditTimelineResponse,
  AuditTimelineEntry,
  AuditSeverity,
  AuditTarget,
  AuditActor,
  AuditTimelineStats,
} from './interfaces/auditService.interface';

type AuditLogWithUser = Prisma.AuditLogGetPayload<{ include: { user: { select: { id: true; name: true; email: true } } } }>;

export class AuditService implements IAuditService {
  private prisma: PrismaClient;
  constructor({ prisma }: { prisma: PrismaClient }) {
    this.prisma = prisma;
  }

  async listAudit(params: AuditListParams): Promise<AuditTimelineResponse> {
    const page = Math.max(1, coerceNumber(params.page, 1));
    const pageSize = Math.min(200, Math.max(1, coerceNumber(params.pageSize, 25)));
    const q = (params.q ?? '').toString().trim();
    const action = (params.action ?? '').toString().trim();
    const userId = (params.userId ?? '').toString().trim();
    const from = params.from ?? null;
    const to = params.to ?? null;

    const where: Prisma.AuditLogWhereInput = {};
  if (action) where.action = { contains: action };
    if (userId) where.userId = userId;
    if (from || to) where.createdAt = { gte: from ?? undefined, lte: to ?? undefined };
    if (q) {
      const containsFilter = { contains: q } as Prisma.StringFilter;
      const orFilters: Prisma.AuditLogWhereInput[] = [
        { action: containsFilter },
        { ipAddress: containsFilter },
        { userAgent: containsFilter },
        { metadata: { string_contains: q } as Prisma.JsonFilter },
        { user: { is: { email: containsFilter } } },
        { user: { is: { name: containsFilter } } },
      ];
      where.OR = [...(where.OR ?? []), ...orFilters];
    }

    const [total, logs] = await Promise.all([
      this.prisma.auditLog.count({ where }),
      this.prisma.auditLog.findMany({
        where,
        include: { user: { select: { id: true, name: true, email: true } } },
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize,
      }),
    ]);

    const items = logs.map(mapAuditLogToEntry);
    const stats = buildTimelineStats(logs);
    return { items, total, page, pageSize, stats };
  }
}

export default AuditService;

function coerceNumber(value: unknown, fallback: number): number {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function mapAuditLogToEntry(row: AuditLogWithUser): AuditTimelineEntry {
  const severity = deriveSeverity(row.action);
  const description = describeAction(row.action, row.metadata ?? null);
  const target = deriveTarget(row.action, row.metadata ?? null);
  const actor = deriveActor(row);
  const tags = deriveTags(row.action);
  return {
    id: row.id,
    action: row.action,
    createdAt: row.createdAt.toISOString(),
    description,
    severity,
    actor,
    target,
    ipAddress: row.ipAddress ?? null,
    userAgent: row.userAgent ?? null,
    metadata: row.metadata ?? null,
    tags,
  };
}

function deriveTags(action: string): string[] {
  const parts = action.split('.').filter(Boolean);
  if (!parts.length) return [];
  const combos: string[] = [];
  for (let i = 0; i < parts.length; i++) {
    combos.push(parts.slice(0, i + 1).join('.'));
  }
  return Array.from(new Set(combos));
}

function deriveActor(row: AuditLogWithUser): AuditActor {
  if (row.user) {
    return {
      id: row.user.id,
      name: row.user.name,
      email: row.user.email,
      initials: computeInitials(row.user.name ?? row.user.email ?? row.user.id ?? ''),
    };
  }
  const fallback = row.userId ? computeInitials(row.userId) : null;
  return {
    id: row.userId ?? undefined,
    initials: fallback,
  };
}

function buildTimelineStats(rows: AuditLogWithUser[]): AuditTimelineStats {
  const severity: Record<AuditSeverity, number> = { info: 0, warning: 0, critical: 0 };
  const actorIds = new Set<string>();
  const actions = new Set<string>();
  let newest: Date | null = null;
  let oldest: Date | null = null;

  for (const row of rows) {
    const sev = deriveSeverity(row.action);
    severity[sev] += 1;
    if (row.userId) actorIds.add(row.userId);
    actions.add(row.action);
    if (!newest || row.createdAt > newest) newest = row.createdAt;
    if (!oldest || row.createdAt < oldest) oldest = row.createdAt;
  }

  return {
    severity,
    uniqueActors: actorIds.size,
    uniqueActions: actions.size,
    range: {
      from: oldest ? oldest.toISOString() : null,
      to: newest ? newest.toISOString() : null,
    },
  };
}

function computeInitials(value?: string | null): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  const segments = trimmed.split(/\s+/).filter(Boolean);
  if (segments.length === 1) {
    const [first] = segments;
    return first.slice(0, 2).toUpperCase();
  }
  return segments
    .slice(0, 2)
    .map(part => part[0]?.toUpperCase() ?? '')
    .join('');
}

function deriveSeverity(action: string): AuditSeverity {
  const normalized = action.toLowerCase();
  const criticalPatterns = [
    'users.lock',
    'users.unlock',
    'login.throttled',
    'login.locked',
    'oauth',
    'password_reset.reset',
  ];
  if (criticalPatterns.some(p => normalized.includes(p))) return 'critical';
  const warningPatterns = [
    'auth.',
    'permissions',
    'settings',
    'menus',
    'menuitems',
  ];
  if (warningPatterns.some(p => normalized.includes(p))) return 'warning';
  return 'info';
}

function describeAction(action: string, metadata: Prisma.JsonValue | null): string {
  const meta = asJsonObject(metadata);
  const roleName = metaString(meta, 'roleName') ?? metaString(meta, 'name');
  const permission = metaString(meta, 'permission');
  const userId = metaString(meta, 'userId');
  const reason = metaString(meta, 'reason');
  const menuName = metaString(meta, 'name');
  const menuId = metaString(meta, 'menuId');
  const menuItemTitle = metaString(meta, 'title');
  const category = metaString(meta, 'category');
  switch (action) {
    case 'admin.roles.upsert':
      return `Role ${roleName ?? 'updated'}`;
    case 'admin.roles.delete':
      return `Role ${roleName ?? 'deleted'}`;
    case 'admin.permissions.grant':
      return `Granted ${permission ?? 'permission'} to ${roleName ?? 'role'}`;
    case 'admin.permissions.revoke':
      return `Revoked ${permission ?? 'permission'} from ${roleName ?? 'role'}`;
    case 'admin.users.assign_role':
      return `Assigned ${roleName ?? 'role'} to user ${userId ?? ''}`.trim();
    case 'admin.users.revoke_role':
      return `Removed ${roleName ?? 'role'} from user ${userId ?? ''}`.trim();
    case 'admin.users.lock':
      return `Locked user ${userId ?? ''}${reason ? ` (${reason})` : ''}`.trim();
    case 'admin.users.unlock':
      return `Unlocked user ${userId ?? ''}`.trim();
    case 'admin.settings.upsert':
      {
        const keysValue = meta?.keys;
        const keyCount = Array.isArray(keysValue) ? keysValue.length : undefined;
        return `Updated ${category ?? 'settings'} (${keyCount ?? 1} ${keyCount === 1 ? 'key' : 'keys'})`;
      }
    case 'admin.menus.create':
      return `Created menu ${menuName ?? menuId ?? ''}`.trim();
    case 'admin.menus.update':
      return `Updated menu ${menuName ?? menuId ?? ''}`.trim();
    case 'admin.menus.delete':
      return `Deleted menu ${menuName ?? menuId ?? ''}`.trim();
    case 'admin.menuItems.create':
      return `Created menu item ${menuItemTitle ?? metaString(meta, 'id') ?? ''}`.trim();
    case 'admin.menuItems.update':
      return `Updated menu item ${menuItemTitle ?? metaString(meta, 'id') ?? ''}`.trim();
    case 'admin.menuItems.delete':
      return `Deleted menu item ${metaString(meta, 'id') ?? ''}`.trim();
    default:
      break;
  }
  if (action.startsWith('auth.login')) {
    return action.includes('throttled') ? 'Login throttled' : 'Login event';
  }
  if (action.startsWith('auth.password_reset')) {
    return action.endsWith('.reset') ? 'Password reset completed' : 'Password reset requested';
  }
  if (action.startsWith('auth.oauth')) {
    return `OAuth event (${action.split('.')?.[2] ?? 'provider'})`;
  }
  if (action.startsWith('auth.')) {
    return `Auth event (${action.split('.').slice(1).join(' ')})`;
  }
  return action.replace(/\./g, ' ');
}

function deriveTarget(action: string, metadata: Prisma.JsonValue | null): AuditTarget | undefined {
  const meta = asJsonObject(metadata);
  if (action.startsWith('admin.roles')) {
    const label = metaString(meta, 'name') ?? metaString(meta, 'roleName');
    const id = metaString(meta, 'id') ?? label;
    return { type: 'role', id, label };
  }
  if (action.startsWith('admin.permissions')) {
    const label = metaString(meta, 'roleName');
    return { type: 'role', id: label, label };
  }
  if (action.startsWith('admin.users')) {
    const id = metaString(meta, 'userId');
    const label = id ?? metaString(meta, 'userEmail');
    return { type: 'user', id, label };
  }
  if (action.startsWith('admin.settings')) {
    const label = metaString(meta, 'category');
    return { type: 'settings', label };
  }
  if (action.startsWith('admin.menus')) {
    const id = metaString(meta, 'id') ?? metaString(meta, 'menuId');
    const label = metaString(meta, 'name') ?? metaString(meta, 'title');
    return { type: 'menu', id, label };
  }
  if (action.startsWith('admin.menuItems')) {
    const id = metaString(meta, 'id');
    const label = metaString(meta, 'title');
    return { type: 'menu_item', id, label };
  }
  if (action.startsWith('auth.')) {
    const label = metaString(meta, 'email') ?? metaString(meta, 'provider');
    return { type: 'session', label };
  }
  return undefined;
}

function asJsonObject(value: Prisma.JsonValue | null): Prisma.JsonObject | undefined {
  return isJsonObject(value) ? value : undefined;
}

function isJsonObject(value: Prisma.JsonValue | null): value is Prisma.JsonObject {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function metaString(meta: Prisma.JsonObject | undefined, key: string): string | undefined {
  if (!meta) return undefined;
  const value = meta[key];
  if (value === null || value === undefined) return undefined;
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return undefined;
}
