import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import pino from 'pino';
import pinoHttp from 'pino-http';
import { PrismaClient } from '@prisma/client';
import petsRouter from './routes/pets';
import sheltersRouter from './routes/shelters';
import locationsRouter from './routes/locations';
import ownersRouter from './routes/owners';
import medicalRouter from './routes/medicalRecords';
import eventsRouter from './routes/events';
import petOwnersRouter from './routes/petOwners';
import adminRouter from './routes/admin';
import authRouter from './routes/auth';
import { parseAuth, requireRole } from './middleware/auth';
// We'll serve ReDoc (Redocly) via a small HTML page instead of using the
// now-unmaintained swagger-ui-express package.
import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';
import { marked } from 'marked';
// Load the OpenAPI YAML spec at runtime. We parse it with js-yaml so the
// source can be hand-edited YAML rather than JSON. If parsing fails we
// set `openapi` to null so the server still starts.
let openapi: any = null;
let openapiAdmin: any = null;
let openapiAuth: any = null;
try {
  const yamlPath = path.join(__dirname, 'openapi-pets.yaml');
  const raw = fs.readFileSync(yamlPath, 'utf8');
  openapi = yaml.load(raw) as any;
} catch (err) {
  openapi = null;
}
// Load the Admin OpenAPI YAML spec at runtime as a separate artifact.
try {
  // Prefer the file alongside the compiled output (dist)
  let adminYamlPath = path.join(__dirname, 'openapi-admin.yaml');
  let raw: string | null = null;
  try {
    raw = fs.readFileSync(adminYamlPath, 'utf8');
  } catch (_) {
    // Fallback: try project src path when running without copied assets
    const srcFallback = path.resolve(process.cwd(), 'src', 'openapi-admin.yaml');
    raw = fs.readFileSync(srcFallback, 'utf8');
    adminYamlPath = srcFallback;
  }
  openapiAdmin = yaml.load(raw!) as any;
} catch (err) {
  openapiAdmin = null;
}
// Load Auth OpenAPI YAML
try {
  let authYamlPath = path.join(__dirname, 'openapi-auth.yaml');
  let raw: string | null = null;
  try {
    raw = fs.readFileSync(authYamlPath, 'utf8');
  } catch (_) {
    const srcFallback = path.resolve(process.cwd(), 'src', 'openapi-auth.yaml');
    raw = fs.readFileSync(srcFallback, 'utf8');
    authYamlPath = srcFallback;
  }
  openapiAuth = yaml.load(raw!) as any;
} catch (err) {
  openapiAuth = null;
}
// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../package.json');

// Avoid setting up the pretty transport in test environments where pino-pretty
// may not be installed or resolvable. Tests set NODE_ENV=test to skip the
// transport and keep the logger simple.
let logger;
if (process.env.NODE_ENV === 'test') {
  logger = pino();
} else {
  // Try to use pino-pretty in non-production/dev if available. If it's not
  // installed (for example in some local setups) fall back to plain pino so
  // the server still starts.
  try {
    // require.resolve will throw if the package cannot be found
    if (process.env.NODE_ENV !== 'production') {
      require.resolve('pino-pretty');
      logger = pino({ transport: { target: 'pino-pretty' } });
    } else {
      logger = pino();
    }
  } catch (err) {
    logger = pino();
  }
}

const app = express();
app.use(express.json());
app.use(helmet());
// Enable CORS with credentials for frontend dev server
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:5173',
  credentials: true,
}));
app.use(cookieParser(process.env.COOKIE_SECRET || 'dev-cookie-secret'));
app.use(rateLimit({ windowMs: 60 * 1000, max: 200 }));
// pino and pino-http have slightly different logger typings across versions;
// cast to `any` to avoid a TS-only type mismatch while keeping runtime behavior.
app.use(pinoHttp({ logger: logger as any }));

// Parse access token from cookies/Authorization and attach req.user
app.use(parseAuth as any);

// -----------------------------
// Request metrics & event loop
// -----------------------------
type Histogram = { buckets: number[]; counts: number[] };
const metrics = {
  reqCount: 0,
  errCount: 0,
  durations: [] as number[],
  // rolling event loop lag samples (ms)
  loopLag: [] as number[],
};

// Simple middleware to record request durations and errors
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  metrics.reqCount++;
  let finished = false;
  const done = () => {
    if (finished) return;
    finished = true;
    const end = process.hrtime.bigint();
    const ms = Number(end - start) / 1e6;
    if (!Number.isNaN(ms) && isFinite(ms)) metrics.durations.push(ms);
    if (res.statusCode >= 500) metrics.errCount++;
    // keep durations bounded to last N samples
    if (metrics.durations.length > 5000) metrics.durations.splice(0, metrics.durations.length - 5000);
  };
  res.on('finish', done);
  res.on('close', done);
  next();
});

// Periodically sample event loop lag
if (process.env.NODE_ENV !== 'test') {
  try {
    // Use perf_hooks if available
    const sampler = async () => {
      try {
        const { performance } = await import('node:perf_hooks');
        const t1 = performance.now();
        setImmediate(() => {
          const t2 = performance.now();
          const lag = Math.max(0, t2 - t1);
          metrics.loopLag.push(lag);
          if (metrics.loopLag.length > 1000) metrics.loopLag.splice(0, metrics.loopLag.length - 1000);
        });
      } catch {
        // fallback: approximate with setTimeout drift
        const ts = Date.now();
        setTimeout(() => {
          const drift = Math.max(0, Date.now() - ts - 100);
          metrics.loopLag.push(drift);
          if (metrics.loopLag.length > 1000) metrics.loopLag.splice(0, metrics.loopLag.length - 1000);
        }, 100);
      }
    };
    setInterval(sampler, 1000).unref();
  } catch {}
}

function percentile(sorted: number[], p: number): number | null {
  if (!sorted.length) return null;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.floor(p * (sorted.length - 1))));
  return sorted[idx];
}

// Admin metrics snapshot endpoint
app.get('/admin/monitoring/metrics', requireRole('system_admin') as any, async (_req, res) => {
  const recent = metrics.durations.slice(-2000).sort((a, b) => a - b);
  const lag = metrics.loopLag.slice(-600);
  const p50 = percentile(recent, 0.5);
  const p90 = percentile(recent, 0.9);
  const p99 = percentile(recent, 0.99);
  res.json({
    requests: {
      count: metrics.reqCount,
      errors: metrics.errCount,
      p50,
      p90,
      p99,
    },
    loopLag: {
      meanMs: lag.length ? lag.reduce((a, b) => a + b, 0) / lag.length : null,
      maxMs: lag.length ? Math.max(...lag) : null,
      samples: lag.slice(-120),
    },
    timestamp: new Date().toISOString(),
  });
});

// Persist selected metrics periodically for charting
const prismaForMetrics = new PrismaClient();
// Track last retention cleanup information and persist to settings
let lastCleanupAt: Date | null = null;
let lastCleanupDeleted: number | null = null;
async function loadRetentionStatus() {
  try {
    const a = await (prismaForMetrics as any).setting.findUnique({ where: { category_key: { category: 'monitoring', key: 'lastCleanupAt' } } });
    const d = await (prismaForMetrics as any).setting.findUnique({ where: { category_key: { category: 'monitoring', key: 'lastCleanupDeleted' } } });
    lastCleanupAt = a?.value ? new Date(String(a.value)) : null;
    lastCleanupDeleted = typeof d?.value === 'number' ? Number(d.value) : (d?.value != null ? Number(d.value) : null);
  } catch {}
}
void loadRetentionStatus();
if (process.env.NODE_ENV !== 'test') {
  setInterval(async () => {
    try {
      const recent = metrics.durations.slice(-100).sort((a, b) => a - b);
      const p99 = percentile(recent, 0.99);
      const errorRate = metrics.reqCount ? metrics.errCount / metrics.reqCount : 0;
      const lag = metrics.loopLag.slice(-60);
      const meanLag = lag.length ? lag.reduce((a, b) => a + b, 0) / lag.length : 0;
      const points: Array<{ metric: string; value: number; labels?: any }> = [];
      if (p99 != null) points.push({ metric: 'http.p99', value: p99 });
      points.push({ metric: 'http.error_rate', value: errorRate });
      points.push({ metric: 'eventloop.lag.mean', value: meanLag });
      if (points.length) {
        await (prismaForMetrics as any).metricPoint.createMany({ data: points.map(p => ({ metric: p.metric, value: p.value, labels: p.labels ?? undefined })) });
      }
    } catch (_err) {
      // ignore sampling errors
    }
  }, 30_000).unref();

  // Periodic retention cleanup for monitoring metrics
  const retentionCleanup = async () => {
    try {
      // Default 7 days if no setting present
      let days = 7;
      try {
        const row = await (prismaForMetrics as any).setting.findUnique({ where: { category_key: { category: 'monitoring', key: 'retentionDays' } } });
        const v = Number(row?.value);
        if (Number.isFinite(v) && v > 0) days = v;
      } catch {}
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
      const result = await (prismaForMetrics as any).metricPoint.deleteMany({ where: { createdAt: { lt: cutoff } } });
      lastCleanupAt = new Date();
      lastCleanupDeleted = Number(result?.count ?? 0);
      try {
        await (prismaForMetrics as any).setting.upsert({
          where: { category_key: { category: 'monitoring', key: 'lastCleanupAt' } },
          create: { category: 'monitoring', key: 'lastCleanupAt', value: lastCleanupAt.toISOString() },
          update: { value: lastCleanupAt.toISOString() },
        });
        await (prismaForMetrics as any).setting.upsert({
          where: { category_key: { category: 'monitoring', key: 'lastCleanupDeleted' } },
          create: { category: 'monitoring', key: 'lastCleanupDeleted', value: lastCleanupDeleted },
          update: { value: lastCleanupDeleted },
        });
      } catch {}
    } catch (err) {
      try { (logger as any).warn({ err }, 'retention cleanup failed'); } catch {}
    }
  };
  // Run hourly; unref so it won't keep the event loop alive
  setInterval(retentionCleanup, 60 * 60 * 1000).unref();
}

// Basic liveness and detail health endpoints
app.get('/health', async (_req, res) => {
  res.json({ status: 'ok' });
});
app.get('/healthz', async (_req, res) => {
  // quick liveness alias
  res.type('text/plain').send('ok');
});
app.get('/readyz', async (_req, res) => {
  // in future, check DB and external dependencies
  res.type('text/plain').send('ready');
});
// Minimal runtime stats for system administrators
app.get('/admin/monitoring/runtime', requireRole('system_admin') as any, async (_req, res) => {
  const mem = process.memoryUsage();
  const cpu = process.cpuUsage();
  const uptimeSec = process.uptime();
  const hr = process.hrtime();
  const versions = process.versions;
  const node = process.version;
  const pid = process.pid;
  const ppid = process.ppid;
  // Event loop delay is available via perf_hooks in newer Node, optional here
  let eventLoopLagMs: number | undefined = undefined;
  try {
    const { monitorEventLoopDelay } = await import('node:perf_hooks');
    const h = monitorEventLoopDelay();
    h.enable();
    // sample briefly
    setTimeout(() => h.disable(), 10);
    eventLoopLagMs = h.mean / 1e6; // ns -> ms
  } catch {}
  res.json({
    status: 'ok',
    pid, ppid,
    node,
    versions,
    uptimeSec,
    hrtime: { sec: hr[0], nsec: hr[1] },
    memory: {
      rss: mem.rss,
      heapTotal: mem.heapTotal,
      heapUsed: mem.heapUsed,
      external: (mem as any).external,
      arrayBuffers: (mem as any).arrayBuffers,
    },
    cpu: {
      userMicros: cpu.user,
      systemMicros: cpu.system,
    },
    eventLoopLagMs,
    retention: {
      lastCleanupAt: lastCleanupAt ? lastCleanupAt.toISOString() : null,
      lastCleanupDeleted,
    },
    timestamp: new Date().toISOString(),
  });
});

// Admin Docs: API changelog (markdown rendered as HTML)
app.get('/admin/docs/api-changelog', requireRole('system_admin') as any, async (_req, res) => {
  try {
    const mdPath = path.resolve(process.cwd(), 'src', 'docs', 'api-changelog.md');
    const raw = fs.readFileSync(mdPath, 'utf8');
    const html = marked.parse(raw);
    res.type('text/html').send(String(html));
  } catch (err) {
    res.status(500).json({ error: 'changelog not available' });
  }
});

// On-demand retention cleanup task
app.post('/admin/monitoring/retention/cleanup', requireRole('system_admin') as any, async (req, res) => {
  try {
    await (async () => {
      // Reuse logic from periodic cleanup
      let days = 7;
      try {
        const row = await (prismaForMetrics as any).setting.findUnique({ where: { category_key: { category: 'monitoring', key: 'retentionDays' } } });
        const v = Number(row?.value);
        if (Number.isFinite(v) && v > 0) days = v;
      } catch {}
      const cutoff = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
      const result = await (prismaForMetrics as any).metricPoint.deleteMany({ where: { createdAt: { lt: cutoff } } });
      lastCleanupAt = new Date();
      lastCleanupDeleted = Number(result?.count ?? 0);
      try {
        await (prismaForMetrics as any).setting.upsert({
          where: { category_key: { category: 'monitoring', key: 'lastCleanupAt' } },
          create: { category: 'monitoring', key: 'lastCleanupAt', value: lastCleanupAt.toISOString() },
          update: { value: lastCleanupAt.toISOString() },
        });
        await (prismaForMetrics as any).setting.upsert({
          where: { category_key: { category: 'monitoring', key: 'lastCleanupDeleted' } },
          create: { category: 'monitoring', key: 'lastCleanupDeleted', value: lastCleanupDeleted },
          update: { value: lastCleanupDeleted },
        });
      } catch {}
    })();
    res.json({ ok: true, lastCleanupAt: lastCleanupAt?.toISOString() ?? null, lastCleanupDeleted });
  } catch (err) {
    try { (logger as any).warn({ err }, 'manual retention cleanup failed'); } catch {}
    res.status(500).json({ error: 'failed to cleanup' });
  }
});

// Query recent persisted metrics (for charts)
app.get('/admin/monitoring/series', requireRole('system_admin') as any, async (req, res) => {
  const { metric = 'http.p99', minutes = '60' } = req.query as any;
  const mins = Math.max(1, Math.min(24 * 60, Number(minutes) || 60));
  const since = new Date(Date.now() - mins * 60 * 1000);
  try {
  const rows = await (prismaForMetrics as any).metricPoint.findMany({
      where: { metric: String(metric), createdAt: { gte: since } },
      orderBy: { createdAt: 'asc' },
      select: { value: true, createdAt: true },
    });
    res.json({ metric, minutes: mins, points: rows });
  } catch (err) {
    res.status(500).json({ error: 'failed to load series' });
  }
});

// Swagger UI - main public docs mounted only in non-production by default.
// Enable in production by setting API_DOCS=true in the environment.
try {
  const enableDocs = process.env.NODE_ENV !== 'production' || process.env.API_DOCS === 'true';
  if (enableDocs) {
      const version = pkg.version || '0.0.0';
      const docsPath = `/api-docs/v${version}`;
      const latestPath = `/api-docs/latest`;
      const authDocsPath = `/auth-docs/v${version}`;
      const authLatestPath = `/auth-docs/latest`;
      if (!openapi) {
        logger.warn('OpenAPI spec not found; skipping docs mount');
      } else {
        // Inject runtime version into the spec so the YAML file can be a
        // static artifact and index.ts controls the actual version string.
        openapi.info = openapi.info || {};
        openapi.info.version = version;
        // raw JSON endpoints
        app.get(`${docsPath}/openapi.json`, (req, res) => res.json(openapi));
        app.get(`${latestPath}/openapi.json`, (req, res) => res.json(openapi));
        // raw YAML endpoints (serve the original YAML file)
        app.get(`${docsPath}/openapi.yaml`, (_req, res) => {
          try {
            const yamlRaw = fs.readFileSync(path.join(__dirname, 'openapi-pets.yaml'), 'utf8');
            res.type('text/yaml').send(yamlRaw);
          } catch (err) {
            res.status(500).send('spec not available');
          }
        });
        app.get(`${latestPath}/openapi.yaml`, (_req, res) => {
          try {
            const yamlRaw = fs.readFileSync(path.join(__dirname, 'openapi-pets.yaml'), 'utf8');
            res.type('text/yaml').send(yamlRaw);
          } catch (err) {
            res.status(500).send('spec not available');
          }
        });
        // Pin ReDoc to a specific release and include Subresource Integrity (SRI).
        // Using a versioned, immutable CDN path is recommended for production.
        const REDOC_VERSION = 'v2.5.1';
        const REDOC_CDN = `https://cdn.redoc.ly/redoc/${REDOC_VERSION}/bundles/redoc.standalone.js`;
        // SHA-384 computed from the exact file at the pinned URL. This ensures the
        // browser verifies the fetched script matches the expected content.
        const REDOC_INTEGRITY = 'sha384-up2uPEo+8XzxuLXKGY4DOk79DbbRclvlcx22QZ60aPWQf8LW69XJ8BWzLFewC05H';

        // ReDoc HTML for both stable 'latest' and versioned paths. ReDoc
        // fetches the JSON spec from the /openapi.json endpoints we provide.
        const redocHtml = (specUrl: string) => `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>API docs</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
  </head>
  <body>
    <redoc spec-url='${specUrl}'></redoc>
              <script src="${REDOC_CDN}"
                      integrity="${REDOC_INTEGRITY}"
                      crossorigin="anonymous"></script>
  </body>
</html>`;

        // A relaxed Content Security Policy for the docs HTML so the
        // ReDoc CDN and Google Fonts can load. We set this header only
        // for the docs endpoints to keep the default tighter CSP for the
        // rest of the API.
        const docsCsp = [
          "default-src 'self'",
          "script-src 'self' https://cdn.redoc.ly",
          "script-src-elem 'self' https://cdn.redoc.ly",
          "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
          "font-src 'self' https://fonts.gstatic.com",
          "img-src 'self' data:",
          "connect-src 'self'",
        ].join('; ');

        app.get(latestPath, (_req, res) => {
          res.set('Content-Security-Policy', docsCsp);
          res.type('text/html').send(redocHtml(`${latestPath}/openapi.json`));
        });

        app.get(docsPath, (_req, res) => {
          res.set('Content-Security-Policy', docsCsp);
          res.type('text/html').send(redocHtml(`${docsPath}/openapi.json`));
        });
        // Redirect /api-docs to latest for a stable default entrypoint
        app.get('/api-docs', (_req, res) => res.redirect(302, latestPath));
        logger.info({ docsPath, latestPath }, 'Swagger UI available');
      }

      // Mount Auth API ReDoc if available
      if (openapiAuth) {
        openapiAuth.info = openapiAuth.info || {};
        openapiAuth.info.version = version;
        app.get(`${authDocsPath}/openapi.json`, (_req, res) => res.json(openapiAuth));
        app.get(`${authLatestPath}/openapi.json`, (_req, res) => res.json(openapiAuth));
        const readAuthYamlRaw = () => {
          try {
            return fs.readFileSync(path.join(__dirname, 'openapi-auth.yaml'), 'utf8');
          } catch (_) {
            return fs.readFileSync(path.resolve(process.cwd(), 'src', 'openapi-auth.yaml'), 'utf8');
          }
        };
        app.get(`${authDocsPath}/openapi.yaml`, (_req, res) => {
          try {
            const yamlRaw = readAuthYamlRaw();
            res.type('text/yaml').send(yamlRaw);
          } catch (err) {
            res.status(500).send('spec not available');
          }
        });
        app.get(`${authLatestPath}/openapi.yaml`, (_req, res) => {
          try {
            const yamlRaw = readAuthYamlRaw();
            res.type('text/yaml').send(yamlRaw);
          } catch (err) {
            res.status(500).send('spec not available');
          }
        });
        const REDOC_VERSION = 'v2.5.1';
        const REDOC_CDN = `https://cdn.redoc.ly/redoc/${REDOC_VERSION}/bundles/redoc.standalone.js`;
        const REDOC_INTEGRITY = 'sha384-up2uPEo+8XzxuLXKGY4DOk79DbbRclvlcx22QZ60aPWQf8LW69XJ8BWzLFewC05H';
        const redocHtml = (specUrl: string) => `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Auth API docs</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
  </head>
  <body>
    <redoc spec-url='${specUrl}'></redoc>
              <script src="${REDOC_CDN}"
                      integrity="${REDOC_INTEGRITY}"
                      crossorigin="anonymous"></script>
  </body>
</html>`;
        const docsCsp = [
          "default-src 'self'",
          "script-src 'self' https://cdn.redoc.ly",
          "script-src-elem 'self' https://cdn.redoc.ly",
          "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
          "font-src 'self' https://fonts.gstatic.com",
          "img-src 'self' data:",
          "connect-src 'self'",
        ].join('; ');
        app.get(authLatestPath, (_req, res) => {
          res.set('Content-Security-Policy', docsCsp);
          res.type('text/html').send(redocHtml(`${authLatestPath}/openapi.json`));
        });
        app.get(authDocsPath, (_req, res) => {
          res.set('Content-Security-Policy', docsCsp);
          res.type('text/html').send(redocHtml(`${authDocsPath}/openapi.json`));
        });
        app.get('/auth-docs', (_req, res) => res.redirect(302, authLatestPath));
        logger.info({ authDocsPath, authLatestPath }, 'Auth Swagger UI available');
      }
  }
} catch (err) {
  // If anything goes wrong mounting docs, don't block the server.
  logger.warn({ err }, 'Failed to mount Swagger UI');
}

// Admin Docs - Always mount (including production) but strictly gate access
// behind the system_admin role. This allows privileged operators to view
// admin-specific documentation in production by default.
try {
  const version = pkg.version || '0.0.0';
  const adminBase = `/api-docs/admin`;
  const adminDocsPath = `${adminBase}/v${version}`;
  const adminLatestPath = `${adminBase}/latest`;
  const adminGuard = requireRole('system_admin');

  if (!openapiAdmin) {
    logger.warn('Admin OpenAPI spec not found; skipping admin docs mount');
  } else {
    // Inject runtime version
    openapiAdmin.info = openapiAdmin.info || {};
    openapiAdmin.info.version = version;

    // raw JSON endpoints
    app.get(`${adminDocsPath}/openapi.json`, adminGuard, (_req, res) => res.json(openapiAdmin));
    app.get(`${adminLatestPath}/openapi.json`, adminGuard, (_req, res) => res.json(openapiAdmin));

    // raw YAML endpoints
    const readAdminYamlRaw = () => {
      try {
        return fs.readFileSync(path.join(__dirname, 'openapi-admin.yaml'), 'utf8');
      } catch (_) {
        return fs.readFileSync(path.resolve(process.cwd(), 'src', 'openapi-admin.yaml'), 'utf8');
      }
    };
    app.get(`${adminDocsPath}/openapi.yaml`, adminGuard, (_req, res) => {
      try {
        const yamlRaw = readAdminYamlRaw();
        res.type('text/yaml').send(yamlRaw);
      } catch (err) {
        res.status(500).send('spec not available');
      }
    });
    app.get(`${adminLatestPath}/openapi.yaml`, adminGuard, (_req, res) => {
      try {
        const yamlRaw = readAdminYamlRaw();
        res.type('text/yaml').send(yamlRaw);
      } catch (err) {
        res.status(500).send('spec not available');
      }
    });

    // Reuse ReDoc setup from above
    const REDOC_VERSION = 'v2.5.1';
    const REDOC_CDN = `https://cdn.redoc.ly/redoc/${REDOC_VERSION}/bundles/redoc.standalone.js`;
    const REDOC_INTEGRITY = 'sha384-up2uPEo+8XzxuLXKGY4DOk79DbbRclvlcx22QZ60aPWQf8LW69XJ8BWzLFewC05H';
    const redocHtml = (specUrl: string) => `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Admin API docs</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
  </head>
  <body>
    <redoc spec-url='${specUrl}'></redoc>
              <script src="${REDOC_CDN}"
                      integrity="${REDOC_INTEGRITY}"
                      crossorigin="anonymous"></script>
  </body>
</html>`;

    const docsCsp = [
      "default-src 'self'",
      "script-src 'self' https://cdn.redoc.ly",
      "script-src-elem 'self' https://cdn.redoc.ly",
      "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data:",
      "connect-src 'self'",
    ].join('; ');

    app.get(adminLatestPath, adminGuard, (_req, res) => {
      res.set('Content-Security-Policy', docsCsp);
      res.type('text/html').send(redocHtml(`${adminLatestPath}/openapi.json`));
    });
    app.get(adminDocsPath, adminGuard, (_req, res) => {
      res.set('Content-Security-Policy', docsCsp);
      res.type('text/html').send(redocHtml(`${adminDocsPath}/openapi.json`));
    });
    app.get(adminBase, adminGuard, (_req, res) => res.redirect(302, adminLatestPath));
    logger.info({ adminDocsPath, adminLatestPath }, 'Admin Swagger UI available');
  }
} catch (err) {
  logger.warn({ err }, 'Failed to mount Admin Swagger UI');
}

app.use('/pets', petsRouter);
app.use('/shelters', sheltersRouter);
app.use('/locations', locationsRouter);
app.use('/owners', ownersRouter);
app.use('/medical', medicalRouter);
app.use('/events', eventsRouter);
app.use('/pet-owners', petOwnersRouter);
app.use('/auth', authRouter);
// Admin SPA fallback: intercept HTML navigations under /admin that are not API
// endpoints and either redirect to Vite in dev or serve the built index.html
// in production. This must come BEFORE mounting the admin router so Express
// doesn't short-circuit with a 404 from the router.
try {
  const acceptWantsHtml = (req: express.Request) => (req.headers.accept?.includes('text/html') ?? false);
  const hasExt = (p: string) => !!path.extname(p);
  // Consider only exact /audit and nested /audit/* as API, not /audit-logs
  const isAdminApiPath = (p: string) =>
    p === '/audit' || p.startsWith('/audit/') ||
    p === '/monitoring' || p.startsWith('/monitoring/') ||
    p === '/docs' || p.startsWith('/docs/');
  const clientDir = path.resolve(__dirname, '../../frontend/dist');
  if (process.env.NODE_ENV !== 'production') {
    app.use('/admin', (req, res, next) => {
      const urlPath = req.path;
      if (req.method === 'GET' && acceptWantsHtml(req) && !hasExt(urlPath) && !isAdminApiPath(urlPath)) {
        return res.redirect(302, `http://localhost:5173/admin${urlPath}${req.url.includes('?') ? '' : ''}`);
      }
      next();
    });
  } else if (fs.existsSync(clientDir)) {
    app.use('/admin', (req, res, next) => {
      const urlPath = req.path;
      if (req.method === 'GET' && acceptWantsHtml(req) && !hasExt(urlPath) && !isAdminApiPath(urlPath)) {
        return res.sendFile(path.join(clientDir, 'index.html'));
      }
      next();
    });
  }
} catch {}
app.use('/admin', adminRouter);

const prisma = new PrismaClient();
const port = process.env.PORT ? Number(process.env.PORT) : 4000;

// -------------------------------------------------
// SPA fallback: serve frontend for non-API HTML GETs
// -------------------------------------------------
// In development, redirect unknown HTML routes to the Vite dev server.
// In production, if the frontend build exists, serve index.html.
try {
  // Only treat actual backend API namespaces as API. Do NOT include the broad '/admin'
  // prefix here, because the frontend has client-routed pages under /admin (e.g. /admin/audit-logs).
  const API_PREFIXES = [
    '/api-docs', '/auth-docs', '/auth', '/pets', '/shelters', '/locations',
    '/owners', '/medical', '/events', '/pet-owners', '/health', '/healthz', '/readyz',
    // Narrow admin API prefixes:
    '/admin/audit', '/admin/monitoring', '/admin/docs'
  ];

  const isApiPath = (p: string) => API_PREFIXES.some((pref) => p === pref || p.startsWith(pref + '/'));
  const isHtmlLike = (req: express.Request) =>
    req.method === 'GET' &&
    // only handle browser navigations asking for HTML
    (req.headers.accept?.includes('text/html') ?? false) &&
    // skip asset files with an extension
    !path.extname(req.path);

  if (process.env.NODE_ENV !== 'production') {
    // Dev: send users to the Vite dev server when they hit the backend with an app route
    app.get('*', (req, res, next) => {
      if (isHtmlLike(req) && !isApiPath(req.path)) {
        const target = `http://localhost:5173${req.path}${req.url.includes('?') ? '' : ''}`;
        return res.redirect(302, target);
      }
      next();
    });
  } else {
    // Prod: serve the built SPA if present
    const clientDir = path.resolve(__dirname, '../../frontend/dist');
    if (fs.existsSync(clientDir)) {
      app.use(express.static(clientDir));
      app.get('*', (req, res, next) => {
        if (isHtmlLike(req) && !isApiPath(req.path)) {
          return res.sendFile(path.join(clientDir, 'index.html'));
        }
        next();
      });
    }
  }
} catch (err) {
  try { (logger as any).warn({ err }, 'Failed to set up SPA fallback'); } catch {}
}

// Start the server unless we're running tests. Tests import the `app`
// directly and use SuperTest, so we shouldn't open a real network port.
if (process.env.NODE_ENV !== 'test') {
  app.listen(port, async () => {
    await prisma.$connect();
    logger.info({ port }, 'Server listening');
  });
}

export default app;
