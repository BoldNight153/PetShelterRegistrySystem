import prisma from '../../prisma/client';

export async function resetRateLimits(): Promise<void> {
  try {
    await prisma.rateLimit.deleteMany();
  } catch {
    // ignore cleanup errors so tests can proceed
  }
}
