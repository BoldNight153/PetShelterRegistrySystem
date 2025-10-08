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
// Load the OpenAPI YAML spec at runtime. We parse it with js-yaml so the
// source can be hand-edited YAML rather than JSON. If parsing fails we
// set `openapi` to null so the server still starts.
let openapi: any = null;
let openapiAdmin: any = null;
try {
  const yamlPath = path.join(__dirname, 'openapi.yaml');
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

app.get('/health', async (req, res) => {
  res.json({ status: 'ok' });
});

// Swagger UI - main public docs mounted only in non-production by default.
// Enable in production by setting API_DOCS=true in the environment.
try {
  const enableDocs = process.env.NODE_ENV !== 'production' || process.env.API_DOCS === 'true';
  if (enableDocs) {
      const version = pkg.version || '0.0.0';
      const docsPath = `/api-docs/v${version}`;
      const latestPath = `/api-docs/latest`;
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
            const yamlRaw = fs.readFileSync(path.join(__dirname, 'openapi.yaml'), 'utf8');
            res.type('text/yaml').send(yamlRaw);
          } catch (err) {
            res.status(500).send('spec not available');
          }
        });
        app.get(`${latestPath}/openapi.yaml`, (_req, res) => {
          try {
            const yamlRaw = fs.readFileSync(path.join(__dirname, 'openapi.yaml'), 'utf8');
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
app.use('/admin', adminRouter);

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
