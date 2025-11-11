type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export type NavigationMenuItem = {
  id: string;
  title: string;
  url?: string | null;
  icon?: string | null;
  target?: string | null;
  external?: boolean | null;
  order?: number | null;
  meta?: JsonValue;
  isVisible?: boolean | null;
  isPublished?: boolean | null;
  locale?: string | null;
  children?: NavigationMenuItem[];
};

export type NavigationMenu = {
  id: string;
  name: string;
  title?: string | null;
  description?: string | null;
  locale?: string | null;
  isActive?: boolean | null;
  items: NavigationMenuItem[];
};

export interface INavigationService {
  listMenus(locale?: string): Promise<NavigationMenu[]>;
  getMenu(name: string): Promise<NavigationMenu | null>;
}
