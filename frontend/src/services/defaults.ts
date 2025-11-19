import authAdapter from './impl/authAdapter';
import adminAdapter from './impl/adminAdapter';
import userAdapter from './impl/userAdapter';
import roleAdapter from './impl/roleAdapter';
import navigationAdapter from './impl/navigationAdapter';
import auditAdapter from './impl/auditAdapter';
import securityAdapter from './impl/securityAdapter';
import notificationAdapter from './impl/notificationAdapter';
import type { IAuthService } from './interfaces/auth.interface';
import type { IAdminService } from './interfaces/admin.interface';
import type { IUserService } from './interfaces/user.interface';
import type { IRoleService } from './interfaces/role.interface';
import type { INavigationService } from './interfaces/navigation.interface';
import type { IAuditLogService } from './interfaces/audit.interface';
import type { IAccountSecurityService } from './interfaces/security.interface';
import type { INotificationService } from './interfaces/notifications.interface';


export type Services = {
  auth: IAuthService;
  admin: IAdminService;
  users?: IUserService;
  roles?: IRoleService;
  navigation: INavigationService;
  audit: IAuditLogService;
  security: IAccountSecurityService;
  notifications: INotificationService;
};

export const defaultServices: Services = {
  auth: authAdapter,
  admin: adminAdapter,
  users: userAdapter,
  roles: roleAdapter,
  navigation: navigationAdapter,
  audit: auditAdapter,
  security: securityAdapter,
  notifications: notificationAdapter,
};
