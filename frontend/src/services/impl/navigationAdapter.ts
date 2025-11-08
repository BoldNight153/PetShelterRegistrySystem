import { fetchMenuByName, fetchMenus } from '@/lib/api';
import type { INavigationService, NavigationMenu } from '../interfaces/navigation.interface';

const navigationAdapter: INavigationService = {
  async listMenus(locale) {
    const menus = await fetchMenus(locale);
    return menus as NavigationMenu[];
  },
  async getMenu(name) {
    const menu = await fetchMenuByName(name);
    return (menu ?? null) as NavigationMenu | null;
  },
};

export default navigationAdapter;
