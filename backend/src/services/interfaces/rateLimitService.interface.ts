export type LimitOptions = {
  scope: string;
  key: string;
  windowMs: number;
  limit: number;
};

export interface IRateLimitService {
  incrementAndCheck(opts: LimitOptions): Promise<{ allowed: boolean; remaining: number; count: number; windowReset: Date }>;
  getCount(opts: Omit<LimitOptions, 'limit'>): Promise<{ count: number; windowStart: Date; windowReset: Date }>;
  resetWindow(scope: string, key: string, windowMs: number): Promise<void>;
}

export default IRateLimitService;

