import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import pino from 'pino';
import pinoHttp from 'pino-http';
import { PrismaClient } from '@prisma/client';
import petsRouter from './routes/pets';

// Avoid setting up the pretty transport in test environments where pino-pretty
// may not be installed or resolvable. Tests set NODE_ENV=test to skip the
// transport and keep the logger simple.
const logger = process.env.NODE_ENV === 'test'
  ? pino()
  : pino({ transport: process.env.NODE_ENV !== 'production' ? { target: 'pino-pretty' } : undefined });

const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors());
app.use(rateLimit({ windowMs: 60 * 1000, max: 200 }));
// pino and pino-http have slightly different logger typings across versions;
// cast to `any` to avoid a TS-only type mismatch while keeping runtime behavior.
app.use(pinoHttp({ logger: logger as any }));

app.get('/health', async (req, res) => {
  res.json({ status: 'ok' });
});

app.use('/pets', petsRouter);

const prisma = new PrismaClient();
const port = process.env.PORT ? Number(process.env.PORT) : 4000;

// Start the server unless we're running tests. Tests import the `app`
// directly and use SuperTest, so we shouldn't open a real network port.
if (process.env.NODE_ENV !== 'test') {
  app.listen(port, async () => {
    await prisma.$connect();
    logger.info({ port }, 'Server listening');
  });
}

export default app;
