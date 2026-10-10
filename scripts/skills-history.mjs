/* global console, process */
// Built-in skill history: skills/_history.json lists the content hash of every earlier
// committed version of each built-in entry, so `syncBuiltinSkills` can tell an unmodified old copy in a user's global
// layer (replace it) from a copy the user edited (keep it). `node scripts/skills-history.mjs` regenerates the file;
// `--check` (run by `pnpm lint`) fails when a committed earlier version is missing. Hashes match `skillEntryHash`.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dirname, '..');
const SKILLS = join(ROOT, 'skills');
const OUT = join(SKILLS, '_history.json');
const git = (...args) => execFileSync('git', args, { cwd: ROOT, encoding: 'buffer', maxBuffer: 64 * 1024 * 1024 });
const sha = (buf) => createHash('sha256').update(buf).digest('hex');

if (!existsSync(join(ROOT, '.git'))) { console.log('skills-history — not a git checkout, skipped'); process.exit(0); }

/** Hash of an entry at a commit: a file's bytes, or a directory's sorted `relpath\0sha256(file)\n` lines. */
function hashAt(rev, name) {
  const listing = git('ls-tree', '-r', '--name-only', rev, '--', `skills/${name}`).toString().split('\n').filter(Boolean);
  if (!listing.length) return null;
  if (listing.length === 1 && listing[0] === `skills/${name}`) return sha(git('show', `${rev}:skills/${name}`));
  const h = createHash('sha256');
  for (const f of listing.sort()) h.update(`${f.slice(`skills/${name}/`.length)}\0${sha(git('show', `${rev}:${f}`))}\n`);
  return h.digest('hex');
}

const names = readdirSync(SKILLS).filter((n) => !n.startsWith('.') && !n.startsWith('_')).sort();
const want = {};
for (const name of names) {
  const revs = git('log', '--format=%H', '--', `skills/${name}`).toString().split('\n').filter(Boolean);
  const head = hashAt('HEAD', name);
  const hashes = new Set();
  for (const rev of revs) {
    const h = hashAt(rev, name);
    if (h && h !== head) hashes.add(h);
  }
  if (hashes.size) want[name] = [...hashes].sort();
}

if (process.argv.includes('--check')) {
  const have = existsSync(OUT) ? JSON.parse(readFileSync(OUT, 'utf8')) : {};
  const missing = Object.entries(want).flatMap(([n, hs]) => hs.filter((h) => !(have[n] ?? []).includes(h)).map((h) => `${n} ${h.slice(0, 12)}`));
  if (missing.length) {
    console.error(`skills-history — skills/_history.json misses earlier versions (run node scripts/skills-history.mjs):\n  ${missing.join('\n  ')}`);
    process.exit(1);
  }
  console.log(`skills-history — ${Object.keys(want).length} entries with earlier versions are listed`);
} else {
  // Keep hashes already listed (versions may come from history that was rewritten), add the missing ones.
  const have = existsSync(OUT) ? JSON.parse(readFileSync(OUT, 'utf8')) : {};
  const merged = {};
  for (const n of [...new Set([...Object.keys(have), ...Object.keys(want)])].sort()) merged[n] = [...new Set([...(have[n] ?? []), ...(want[n] ?? [])])].sort();
  writeFileSync(OUT, JSON.stringify(merged, null, 1) + '\n');
  console.log(`skills-history — wrote ${Object.keys(merged).length} entries`);
}
