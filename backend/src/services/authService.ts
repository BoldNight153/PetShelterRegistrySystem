import crypto from 'crypto';
import type { PrismaClient, RefreshToken, VerificationToken, User, Prisma } from '@prisma/client';
import type { IAuthService } from './interfaces/authService.interface';

export class AuthService implements IAuthService {
  prisma: PrismaClient;
  constructor(opts: { prisma: PrismaClient }) {
    this.prisma = opts.prisma;
  }

  generateToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  async createRefreshToken(userId: string, token: string, expiresAt: Date, userAgent?: string, ipAddress?: string): Promise<RefreshToken> {
    return this.prisma.refreshToken.create({ data: { userId, token, expiresAt, userAgent, ipAddress } });
  }

  async revokeRefreshToken(token: string): Promise<RefreshToken> {
    return this.prisma.refreshToken.update({ where: { token }, data: { revokedAt: new Date() } });
  }

  async findRefreshToken(token: string): Promise<RefreshToken | null> {
    return this.prisma.refreshToken.findUnique({ where: { token } });
  }

  async revokeAllRefreshTokens(userId: string) {
    return this.prisma.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
  }

  // verification token helpers
  async createVerificationToken(identifier: string, token: string, type: string, expiresAt: Date): Promise<VerificationToken> {
    return this.prisma.verificationToken.create({ data: { identifier, token, type, expiresAt } });
  }

  async findVerificationToken(token: string): Promise<VerificationToken | null> {
    return this.prisma.verificationToken.findUnique({ where: { token } });
  }

  async consumeVerificationToken(id: string): Promise<VerificationToken> {
    return this.prisma.verificationToken.update({ where: { id }, data: { consumedAt: new Date() } });
  }

  // user locks
  async createUserLock(userId: string, reason: string, manual = false, expiresAt?: Date) {
    return this.prisma.userLock.create({ data: { userId, reason, manual, lockedAt: new Date(), expiresAt: expiresAt ?? null } });
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({ where: { email } });
  }

  async createUser(data: Prisma.UserCreateInput | Prisma.UserUncheckedCreateInput): Promise<User> {
    return this.prisma.user.create({ data });
  }

  async updateUser(id: string, data: Prisma.UserUpdateInput | Prisma.UserUncheckedUpdateInput): Promise<User> {
    return this.prisma.user.update({ where: { id }, data });
  }
}
