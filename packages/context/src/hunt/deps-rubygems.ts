// RubyGems declared dependencies. Read as text, never evaluated (no Bundler):
// - manifest: Gemfile / gems.rb `gem 'name'[, 'version']` (a version only when pinned exactly: `'1.2.3'` / `'= 1.2.3'`);
// - lock: Gemfile.lock / gems.locked — the `specs:` of the `GEM` section (`    name (1.2.3)`, platform suffixes
//   dropped). `GIT` / `PATH` gems are not on rubygems.org and are skipped.
import type { Declared, EcosystemReader } from './deps.js';

const EXACT_RE = /^=?\s*(\d+(?:\.\d+)*(?:\.[A-Za-z]+\d*)?)$/;
const PLATFORM_RE = /-(?:x86_64|x86|aarch64|arm64|arm|universal|java|x64|mingw|mswin|darwin|linux|musl)[\w.-]*$/;

function gemfile(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/(^|\s)#.*$/, '');
    const m = /^\s*gem\s*\(?\s*['"]([\w.-]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/.exec(line);
    if (!m) return;
    if (/\b(path|git|github):/.test(line)) return;
    const v = m[2] ? EXACT_RE.exec(m[2].trim()) : null;
    out.push({ ecosystem: 'rubygems', name: m[1]!, version: v ? v[1]! : null, path, line: i + 1 });
  });
  return out;
}

function lockfile(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  let section = '';
  let inSpecs = false;
  text.split('\n').forEach((raw, i) => {
    if (/^\S/.test(raw)) { section = raw.trim(); inSpecs = false; return; }
    if (/^ {2}specs:\s*$/.test(raw)) { inSpecs = true; return; }
    if (section !== 'GEM' || !inSpecs) return;
    const m = /^ {4}([\w.-]+) \(([^)]+)\)\s*$/.exec(raw);
    if (!m) return;
    out.push({ ecosystem: 'rubygems', name: m[1]!, version: m[2]!.replace(PLATFORM_RE, ''), path, line: i + 1 });
  });
  return out;
}

export const RUBYGEMS_READER: EcosystemReader = {
  ecosystem: 'rubygems',
  kind: (base) => (base === 'Gemfile' || base === 'gems.rb' ? 'manifest' : base === 'Gemfile.lock' || base === 'gems.locked' ? 'lock' : null),
  read: (path, text) => (/(Gemfile\.lock|gems\.locked)$/.test(path) ? lockfile(path, text) : gemfile(path, text)),
};
