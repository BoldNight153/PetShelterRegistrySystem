import prismaClient from '../../../src/prisma/client';

/**
 * Runs the provided callback inside a Prisma interactive transaction and then forces a rollback.
 *
 * Usage: await withTestTransaction(async (tx) => { await tx.user.create(...); // assertions });
 * The transaction will be rolled back, so the DB state remains unchanged after the helper returns.
 *
 * Notes:
 * - This helper is intended for unit/service tests where the test code can use the provided `tx` client.
 * - It is not automatically usable for integration tests that exercise the running HTTP server unless
 *   that server is started with the provided `tx` client wired into its DI container.
 */
export async function withTestTransaction<T>(fn: (tx: typeof prismaClient) => Promise<T>): Promise<T | undefined> {
  let result: T | undefined;
  try {
    await prismaClient.$transaction(async (tx) => {
      // run the test callback and capture the result
      result = await fn(tx as typeof prismaClient);
      // throw a sentinel error to force a rollback of the transaction
      throw new Error('PRISMA_TEST_ROLLBACK');
    });
  } catch (err: any) {
    // Swallow the sentinel rollback error; rethrow others
    if (err && err.message === 'PRISMA_TEST_ROLLBACK') {
      return result;
    }
    throw err;
  }
  return result;
}

export default withTestTransaction;
