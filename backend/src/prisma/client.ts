import { PrismaClient } from '@prisma/client';

// Single shared Prisma client for the app. Import this from services or register in DI.
export const prismaClient = new PrismaClient();

export default prismaClient;
