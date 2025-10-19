import { Container } from 'awilix';

declare global {
  namespace Express {
    interface Request {
      container?: Container;
      user?: { id: string; [key: string]: any } | null;
      log?: { error?: (...args: any[]) => void };
    }
  }
}

export {};
