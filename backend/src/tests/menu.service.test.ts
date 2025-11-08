import MenuService from '../services/menuService';

describe('MenuService', () => {
  describe('buildTree', () => {
    it('builds a nested tree from flat items and sorts by order', () => {
      const items: Parameters<typeof MenuService.buildTree>[0] = [
        { id: 'a', menuId: 'm', parentId: null, title: 'Root A', url: null, order: 2, icon: null, isVisible: true, isPublished: true, meta: null, createdAt: new Date(), updatedAt: new Date() },
        { id: 'b', menuId: 'm', parentId: null, title: 'Root B', url: null, order: 3, icon: null, isVisible: true, isPublished: true, meta: null, createdAt: new Date(), updatedAt: new Date() },
        { id: 'a1', menuId: 'm', parentId: 'a', title: 'Child A1', url: null, order: 1, icon: null, isVisible: true, isPublished: true, meta: null, createdAt: new Date(), updatedAt: new Date() },
      ];

      const tree = MenuService.buildTree(items);
      expect(tree).toHaveLength(2);
      // Root 'a' should come before 'b' because order 2 < 3
      expect(tree[0].id).toBe('a');
      expect(tree[0].children).toHaveLength(1);
      expect(tree[0].children![0].id).toBe('a1');
    });
  });

  describe('listMenus', () => {
    it('returns menus with nested items by grouping items per menu', async () => {
      const fakePrisma: any = {
        menu: {
          findMany: jest.fn().mockResolvedValue([{ id: 'm1', name: 'main', title: 'Main', locale: 'en', isActive: true }]),
        },
        menuItem: {
          findMany: jest.fn().mockResolvedValue([
            { id: 'i1', menuId: 'm1', parentId: null, title: 'Home', url: '/', order: 1, icon: null, isVisible: true, isPublished: true, meta: null, createdAt: new Date(), updatedAt: new Date() },
            { id: 'i2', menuId: 'm1', parentId: null, title: 'About', url: '/about', order: 2, icon: null, isVisible: true, isPublished: true, meta: null, createdAt: new Date(), updatedAt: new Date() },
            { id: 'i1-1', menuId: 'm1', parentId: 'i1', title: 'Sub Home', url: '/home/sub', order: 1, icon: null, isVisible: true, isPublished: true, meta: null, createdAt: new Date(), updatedAt: new Date() },
          ]),
        },
      };

      const svc = new MenuService({ prisma: fakePrisma });
      const menus = await svc.listMenus();
      expect(Array.isArray(menus)).toBe(true);
      expect(menus).toHaveLength(1);
      const menu = menus[0] as any;
      expect(menu.id).toBe('m1');
      expect(menu.items).toBeDefined();
      expect(menu.items.length).toBe(2);
      const home = menu.items.find((it: any) => it.id === 'i1');
      expect(home.children).toHaveLength(1);
      expect(home.children[0].id).toBe('i1-1');
    });
  });
});
