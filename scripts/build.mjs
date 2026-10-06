// Application build: syntax-check every source file with node --check and
// stage a deployable tree under dist/. Zero-dependency ESM, so no bundler.
import { spawnSync } from 'node:child_process';
import { cp, mkdir, rm, writeFile, readdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const srcDir = path.join(root, 'src');
const distDir = path.join(root, 'dist');

async function listJs(dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await listJs(full));
    else if (entry.name.endsWith('.mjs') || entry.name.endsWith('.js')) files.push(full);
  }
  return files;
}

const files = await listJs(srcDir);
let failed = false;
for (const file of files) {
  const r = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (r.status !== 0) {
    failed = true;
    console.error(`syntax check failed: ${path.relative(root, file)}\n${r.stderr}`);
  } else {
    console.log(`syntax ok: ${path.relative(root, file)}`);
  }
}
if (failed) process.exit(1);

if (existsSync(distDir)) await rm(distDir, { recursive: true });
await mkdir(distDir, { recursive: true });
await cp(srcDir, path.join(distDir, 'src'), { recursive: true });
await cp(path.join(root, 'package.json'), path.join(distDir, 'package.json'));
await writeFile(
  path.join(distDir, 'build-info.json'),
  JSON.stringify({ name: 'mpegts-audit', builtAt: new Date().toISOString(), node: process.version }, null, 2) + '\n',
);
console.log(`build complete -> ${path.relative(root, distDir)}/`);
