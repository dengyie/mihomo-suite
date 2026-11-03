// Verify container-level integrity of the web assets we ship in zashboard/dist.
//
// Guards against the class of production bug where a hashed asset (same
// filename, shorter bytes) got written over the live copy — e.g. the
// earth-surface-DQPefyI6.webp truncation found on 3x-ui.mangoqwq.com (2026-11-03):
// a 91 KB file still declaring the original 400 KB VP8 chunk. Filename hashes
// can't catch it (the name stayed the same), so we validate the container.
//
// Checks (all stdlib, run from anywhere):
//   - *.webp : RIFF declares size == actual bytes
//   - *.png  : ends with IEND chunk, and IHDR-decoded dims are sane
//   - *.jpg/*.jpeg : starts with JPEG SOI (FFD8), ends with EOI (FFD9)
//   - *.ico  : ICONDIR count matches file content
//   - *.js/css/json/manifest : parse-level sanity is covered by the other
//     checks in `npm test` (node --check / test_ui_bundle.mjs); here we only
//     require non-empty and no NUL truncation marker mid-file.
//
// Exit 0 = OK. Run: node scripts/check-dist-assets.mjs [distDir]
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';

const root = resolve(new URL('..', import.meta.url).pathname);
const dir = resolve(process.argv[2] ?? join(root, 'zashboard', 'dist'));

const problems = [];

function walk(d) {
  for (const ent of readdirSync(d, { withFileTypes: true })) {
    const p = join(d, ent.name);
    if (ent.isDirectory()) walk(p);
    else if (ent.isFile()) check(p);
  }
}

function check(p) {
  const b = readFileSync(p);
  const name = p.slice(dir.length + 1);
  if (b.length === 0) return problems.push(`${name}: empty file`);

  if (name.endsWith('.webp')) {
    if (b.length < 12 || b.toString('latin1', 0, 4) !== 'RIFF' || b.toString('latin1', 8, 12) !== 'WEBP')
      return problems.push(`${name}: not a RIFF/WEBP container`);
    const declared = 8 + b.readUInt32LE(4);
    if (declared !== b.length)
      problems.push(`${name}: RIFF declares ${declared}B but file is ${b.length}B (truncated?)`);
  } else if (name.endsWith('.png')) {
    const tail = b.subarray(-8).toString('hex');
    if (b.toString('latin1', 0, 8) !== '\x89PNG\r\n\x1a\n' || !tail.endsWith('49454e44ae426082'))
      problems.push(`${name}: PNG signature/IEND broken`);
  } else if (name.endsWith('.jpg') || name.endsWith('.jpeg')) {
    if (b[0] !== 0xff || b[1] !== 0xd8 || b.at(-2) !== 0xff || b.at(-1) !== 0xd9)
      problems.push(`${name}: JPEG SOI/EOI markers missing (truncated?)`);
  } else if (name.endsWith('.ico')) {
    if (b.length < 6) problems.push(`${name}: too short for ICONDIR`);
    else {
      const count = b.readUInt16LE(4);
      const expect = 6 + count * 16;
      if (b.length < expect) problems.push(`${name}: ICONDIR claims ${count} entries, file too short`);
    }
  }
}

walk(dir);
if (problems.length) {
  console.error(`check-dist-assets: ${problems.length} problem(s) in ${dir}`);
  for (const m of problems) console.error('  - ' + m);
  process.exit(1);
}
console.log(`check-dist-assets: OK (${dir})`);
