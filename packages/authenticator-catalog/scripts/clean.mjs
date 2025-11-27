import { rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distPath = path.resolve(__dirname, '..', 'dist');

try {
  rmSync(distPath, { recursive: true, force: true });
} catch (error) {
  // Swallow ENOENT to keep clean idempotent.
  if (error && error.code !== 'ENOENT') {
    throw error;
  }
}
