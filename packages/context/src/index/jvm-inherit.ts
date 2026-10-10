// Spring mappings inherited from interfaces and unannotated base classes, across files and between
// Java and Kotlin. Spring merges `@RequestMapping` / `@GetMapping`… declared on an implemented interface or a
// superclass into the controller's handler methods (OpenAPI generator: `interface PetApi { @GetMapping("/pet/{id}") … }`
// + `@RestController class PetApiController implements PetApi`). The extractors record those mappings and the
// type facts (`FileExtract.inheritedMappings` / `jvmTypes`); this pass adds one entry per controller that inherits
// one, with the implementing method as handler when the controller (or a base class between) overrides it.
import type { FileExtract, JvmTypeFacts, RawEntry } from './types.js';
import { joinRoute } from './types.js';

const MAX_DEPTH = 12;

export function addInheritedSpringEntries(files: FileExtract[]): void {
  const mappings = new Map<string, NonNullable<FileExtract['inheritedMappings']>>();
  for (const f of files) for (const m of f.inheritedMappings ?? []) push(mappings, m.owner, m);
  if (!mappings.size) return;
  const types = new Map<string, JvmTypeFacts[]>();
  for (const f of files) for (const t of f.jvmTypes ?? []) push(types, t.name, t);
  const pathOf = new Map<string, string>();
  for (const f of files) for (const s of f.symbols) pathOf.set(s.symbolId, s.path);

  for (const f of files) {
    for (const ctl of f.jvmTypes ?? []) {
      if (!ctl.controller || !ctl.supers.length) continue;
      // Ancestors nearest first (breadth first), by simple name.
      const names: string[] = [];
      const chain: JvmTypeFacts[] = [];
      const seen = new Set([ctl.name]);
      let level = [...ctl.supers];
      for (let depth = 0; depth < MAX_DEPTH && level.length; depth++) {
        const next: string[] = [];
        for (const n of level) {
          if (seen.has(n)) continue;
          seen.add(n);
          names.push(n);
          for (const t of types.get(n) ?? []) { chain.push(t); next.push(...t.supers); }
        }
        level = next;
      }
      const prefixes = ctl.prefixes ?? chain.find((t) => t.prefixes)?.prefixes ?? [''];
      const implementers = [ctl, ...chain.filter((t) => t.kind === 'class')];
      const done = new Set<string>();
      for (const n of names) {
        for (const m of mappings.get(n) ?? []) {
          // Nearest override (the declaring method itself is not one).
          const found = implementers.flatMap((t) => t.methods).find((x) => x.name === m.method && x.arity === m.arity);
          const impl = found && found.symbolId !== m.symbolId ? found : undefined;
          if (impl?.mapped) continue; // the override carries its own mapping: already an entry
          const handler = impl ?? m;
          for (const prefix of prefixes) {
            const pathTemplate = joinRoute(prefix, m.path);
            const key = `${m.httpMethod} ${pathTemplate}|${handler.symbolId}`;
            if (done.has(key)) continue;
            done.add(key);
            const entry: RawEntry = {
              ruleId: m.ruleId, framework: 'spring', httpMethod: m.httpMethod, pathTemplate,
              handler: { symbolId: handler.symbolId }, path: pathOf.get(handler.symbolId) ?? f.path, range: handler.range,
              middlewares: [], authSignals: [...new Set([...m.authSignals, ...(impl?.authSignals ?? []), ...ctl.classAuth])],
            };
            f.entries.push(entry);
          }
        }
      }
    }
  }
}

function push<K, V>(m: Map<K, V[]>, k: K, v: V): void {
  const arr = m.get(k);
  if (arr) arr.push(v);
  else m.set(k, [v]);
}
