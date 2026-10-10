// crates.io declared dependencies. Read as text, never evaluated (no cargo, no build scripts):
// - manifest: Cargo.toml `[dependencies]` / `[dev-dependencies]` / `[build-dependencies]` / `[workspace.dependencies]` /
//   `[target.*.dependencies]` (a version only when pinned exactly: `"=1.2.3"`); `path` / `git` dependencies skipped;
// - lock: Cargo.lock `[[package]]` entries from the crates.io registry (`source = "registry+…crates.io-index"` or the
//   sparse index); workspace members (no source) and git sources skipped.
import type { Declared, EcosystemReader } from './deps.js';

const lineAt = (text: string, index: number) => text.slice(0, index).split('\n').length;

function manifest(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  let inDeps = false;
  let table: { name: string; line: number; body: string[] } | null = null;
  const flushTable = () => {
    if (!table) return;
    const body = table.body.join('\n');
    if (!/\b(path|git)\s*=/.test(body)) {
      const v = /^\s*version\s*=\s*"=\s*([^"]+)"/m.exec(body);
      out.push({ ecosystem: 'cargo', name: table.name, version: v ? v[1]!.trim() : null, path, line: table.line });
    }
    table = null;
  };
  text.split('\n').forEach((raw, i) => {
    const line = raw.replace(/#.*$/, '').trim();
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header) {
      flushTable();
      const h = header[1]!.trim();
      const sub = /^(?:workspace\.|target\..+\.)?(?:dev-|build-)?dependencies\.([\w-]+)$/.exec(h);
      if (sub) { table = { name: sub[1]!, line: i + 1, body: [] }; inDeps = false; return; }
      inDeps = /^(?:workspace\.|target\..+\.)?(?:dev-|build-)?dependencies$/.test(h);
      return;
    }
    if (table) { table.body.push(line); return; }
    if (!inDeps) return;
    const kv = /^([\w-]+)\s*=\s*(.+)$/.exec(line);
    if (!kv) return;
    const value = kv[2]!.trim();
    if (/\b(path|git)\s*=/.test(value)) return;
    const pinned = /^"=\s*([^"]+)"$/.exec(value) ?? /\bversion\s*=\s*"=\s*([^"]+)"/.exec(value);
    out.push({ ecosystem: 'cargo', name: /\bpackage\s*=\s*"([^"]+)"/.exec(value)?.[1] ?? kv[1]!, version: pinned ? pinned[1]!.trim() : null, path, line: i + 1 });
  });
  flushTable();
  return out;
}

function lock(path: string, text: string): Declared[] {
  const out: Declared[] = [];
  for (const m of text.matchAll(/^\[\[package\]\]\s*$([\s\S]*?)(?=^\[\[|(?![\s\S]))/gm)) {
    const body = m[1]!;
    const name = /^name\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(body)?.[1];
    const source = /^source\s*=\s*"([^"]+)"/m.exec(body)?.[1] ?? '';
    if (!name || !version || !/^(registry\+|sparse\+).*crates\.io/.test(source)) continue;
    out.push({ ecosystem: 'cargo', name, version, path, line: lineAt(text, m.index!) });
  }
  return out;
}

export const CARGO_READER: EcosystemReader = {
  ecosystem: 'cargo',
  kind: (base) => (base === 'Cargo.toml' ? 'manifest' : base === 'Cargo.lock' ? 'lock' : null),
  read: (path, text) => (path.endsWith('Cargo.lock') ? lock(path, text) : manifest(path, text)),
};
