#!/usr/bin/env ts-node
import fs from 'fs';
import path from 'path';
import yaml from 'js-yaml';

function fail(msg: string): never {
  console.error(`\x1b[31mError:\x1b[0m ${msg}`);
  process.exit(1);
}

function main() {
  const root = path.resolve(__dirname, '..');
  const pkgPath = path.join(root, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { version: string };
  const expected = pkg.version;
  const files = [
    path.join(root, 'src', 'openapi-pets.yaml'),
    path.join(root, 'src', 'openapi-auth.yaml'),
    path.join(root, 'src', 'openapi-admin.yaml'),
  ];
  const mismatches: Array<{ file: string; found: string | null }> = [];
  for (const f of files) {
    if (!fs.existsSync(f)) fail(`Spec file missing: ${f}`);
    const raw = fs.readFileSync(f, 'utf8');
    const doc: any = yaml.load(raw);
    const found: string | null = doc?.info?.version ?? null;
    if (found !== expected) mismatches.push({ file: path.relative(root, f), found });
  }
  if (mismatches.length) {
    console.error('OpenAPI info.version must match backend package.json version.');
    for (const m of mismatches) {
      console.error(` - ${m.file}: found ${m.found ?? 'null'}; expected ${expected}`);
    }
    process.exit(2);
  }
  console.log(`All OpenAPI specs match backend version ${expected}.`);
}

main();
