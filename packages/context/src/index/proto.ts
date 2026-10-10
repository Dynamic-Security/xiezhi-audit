// gRPC services declared in the snapshot's .proto files: the service implementations the
// extractors find (Java `XxxImplBase`, Go `UnimplementedXxxServer`, C# `Xxx.XxxBase`) take their full name
// (`package.Service`) and canonical rpc names from here. Text scan; never compiled.
import type { SnapshotView } from '../snapshot/view.js';

export interface GrpcService {
  /** Simple service name (`Greeter`). */
  name: string;
  /** `helloworld.Greeter` (no package → the simple name). */
  fullName: string;
  /** rpc names as declared (`SayHello`). */
  rpcs: string[];
  /** `option (google.api.http)` bindings per rpc (grpc-gateway / kratos HTTP transcoding); absent when none. */
  http?: Record<string, { method: string; path: string }[]>;
}

/** Index of the `}` closing the `{` at `open` (comments already stripped; strings may hold braces only in paths). */
function closeBrace(text: string, open: number): number {
  let depth = 0;
  let quote = false;
  for (let i = open; i < text.length; i++) {
    const ch = text[i]!;
    if (ch === '"' && text[i - 1] !== '\\') quote = !quote;
    if (quote) continue;
    if (ch === '{') depth++;
    else if (ch === '}' && --depth === 0) return i;
  }
  return text.length;
}

/** `/v1/{name=projects/*}/books` → `/v1/{name}/books` (field paths keep their name). */
const httpPath = (p: string) => p.replace(/\{([\w.]+)=[^}]*\}/g, '{$1}');

export function scanProto(text: string): GrpcService[] {
  const clean = text.replace(/\/\/[^\n]*|\/\*[\s\S]*?\*\//g, '');
  const pkg = /\bpackage\s+([\w.]+)\s*;/.exec(clean)?.[1];
  const out: GrpcService[] = [];
  // service bodies by brace matching (rpc option blocks no longer end the service early).
  for (const s of clean.matchAll(/\bservice\s+(\w+)\s*\{/g)) {
    const open = s.index! + s[0].length - 1;
    const body = clean.slice(open + 1, closeBrace(clean, open));
    const rpcs: string[] = [];
    const http: Record<string, { method: string; path: string }[]> = {};
    for (const r of body.matchAll(/\brpc\s+(\w+)\s*\(/g)) {
      rpcs.push(r[1]!);
      // The rpc's own `{ … }` block (options), if any, before the next `rpc` / `;`.
      const after = body.slice(r.index!);
      const brace = after.search(/[{;]/);
      if (brace < 0 || after[brace] !== '{') continue;
      const block = after.slice(brace, closeBrace(after, brace) + 1);
      if (!/google\.api\.http/.test(block)) continue;
      const binds: { method: string; path: string }[] = [];
      for (const b of block.matchAll(/\b(get|post|put|delete|patch)\s*:\s*"([^"]*)"/g)) binds.push({ method: b[1]!.toUpperCase(), path: httpPath(b[2]!) });
      for (const c of block.matchAll(/\bcustom\s*:?\s*\{\s*kind\s*:\s*"(\w+)"\s*,?\s*path\s*:\s*"([^"]*)"/g)) binds.push({ method: c[1]!.toUpperCase(), path: httpPath(c[2]!) });
      if (binds.length) http[r[1]!] = binds;
    }
    out.push({ name: s[1]!, fullName: pkg ? `${pkg}.${s[1]}` : s[1]!, rpcs, ...(Object.keys(http).length ? { http } : {}) });
  }
  return out;
}

export function grpcServicesOf(view: SnapshotView): GrpcService[] {
  const out: GrpcService[] = [];
  for (const f of view.listFiles()) {
    if (!f.path.endsWith('.proto') || f.size > 1024 * 1024) continue;
    try { out.push(...scanProto(view.text(f.path))); } catch { /* unreadable */ }
  }
  return out;
}

/**
 * The rpc entry for an implementation method: the proto service with this simple name (ambiguous names keep the
 * simple name) and the rpc whose name matches case-insensitively (Java implements `SayHello` as `sayHello`).
 * Without proto files the simple service name and the method name (first letter upper-cased) are used; with a
 * proto that does not declare the method, null (a helper method, not an rpc).
 */
export function rpcOf(services: GrpcService[] | undefined, service: string, method: string): { service: string; method: string } | null {
  const cands = (services ?? []).filter((s) => s.name === service);
  const upper = method.charAt(0).toUpperCase() + method.slice(1);
  if (!cands.length) return { service, method: upper };
  const rpc = cands[0]!.rpcs.find((r) => r.toLowerCase() === method.toLowerCase());
  if (!rpc) return null;
  return { service: cands.length === 1 ? cands[0]!.fullName : service, method: rpc };
}
