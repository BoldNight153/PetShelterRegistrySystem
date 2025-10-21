import authAdapter from './impl/authAdapter';
import adminAdapter from './impl/adminAdapter';
import userAdapter from './impl/userAdapter';
import roleAdapter from './impl/roleAdapter';
import type { IAuthService } from './interfaces/auth.interface';
import type { IAdminService } from './interfaces/admin.interface';
import type { IUserService } from './interfaces/user.interface';
import type { IRoleService } from './interfaces/role.interface';

export type Services = {
  auth: IAuthService;
  admin: IAdminService;
  users?: IUserService;
  roles?: IRoleService;
};

export const defaultServices: Services = {
  auth: authAdapter,
  admin: adminAdapter,
  users: userAdapter,
  roles: roleAdapter,
};
