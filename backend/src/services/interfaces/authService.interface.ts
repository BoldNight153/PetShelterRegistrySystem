import type { RefreshToken, VerificationToken, User, UserLock, Prisma } from '@prisma/client';

export interface IAuthService {
  generateToken(): string;
  createRefreshToken(userId: string, token: string, expiresAt: Date, userAgent?: string, ipAddress?: string): Promise<RefreshToken>;
  revokeRefreshToken(token: string): Promise<RefreshToken>;
  findRefreshToken(token: string): Promise<RefreshToken | null>;
  revokeAllRefreshTokens(userId: string): Promise<Prisma.BatchPayload>;

  createVerificationToken(identifier: string, token: string, type: string, expiresAt: Date): Promise<VerificationToken>;
  findVerificationToken(token: string): Promise<VerificationToken | null>;
  consumeVerificationToken(id: string): Promise<VerificationToken>;

  createUserLock(userId: string, reason: string, manual?: boolean, expiresAt?: Date): Promise<UserLock>;
  findUserByEmail(email: string): Promise<User | null>;
  createUser(data: Prisma.UserCreateInput | Prisma.UserUncheckedCreateInput): Promise<User>;
  updateUser(id: string, data: Prisma.UserUpdateInput | Prisma.UserUncheckedUpdateInput): Promise<User>;
}

export default IAuthService;
