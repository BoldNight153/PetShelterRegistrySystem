import * as Icons from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

import type { NavLinkItem, NavMainItem } from '@/components/nav-main';
import type { NavigationMenuItem } from '@/services/interfaces/navigation.interface';

const iconRegistry = Icons as unknown as Record<string, LucideIcon>;

function isExternalUrl(url: string): boolean {
  return /^(https?:\/\/|mailto:|tel:)/i.test(url);
}

function toNavLink(item: NavigationMenuItem, includeIcon: boolean): NavLinkItem {
  const url = item.url ?? '#';
  const explicitExternal = Boolean(item.external);
  const inferredExternal = isExternalUrl(url);
  const external = explicitExternal || inferredExternal;
  const target = item.target ?? (external ? '_blank' : undefined);
  return {
    title: item.title,
    url,
    icon: includeIcon ? resolveIcon(item.icon) : undefined,
    external,
    target,
  };
}

export function resolveIcon(identifier?: string | null): LucideIcon | undefined {
  if (!identifier) return undefined;
  const direct = iconRegistry[identifier];
  if (direct) return direct;
  const pascal = identifier
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean)
    .map((segment) => segment.charAt(0).toUpperCase() + segment.slice(1))
    .join('');
  return iconRegistry[pascal];
}

export function mapMenuToNavMain(items: NavigationMenuItem[]): NavMainItem[] {
  return items.map((item) => ({
    ...toNavLink(item, true),
    items: (item.children ?? []).map((child) => toNavLink(child, true)),
  }));
}

export type ProjectNavItem = {
  name: string;
  url: string;
  icon: LucideIcon;
  external?: boolean;
  target?: string | null;
};

export function mapToProjectNav(items: NavigationMenuItem[], fallbackIcon: LucideIcon): ProjectNavItem[] {
  return items
    .filter((item) => Boolean(item.title))
    .map((item) => ({
      name: item.title,
      url: item.url ?? '#',
      icon: resolveIcon(item.icon) ?? fallbackIcon,
      external: Boolean(item.external) || isExternalUrl(item.url ?? ''),
      target: item.target ?? (Boolean(item.external) || isExternalUrl(item.url ?? '') ? '_blank' : undefined),
    }));
}
