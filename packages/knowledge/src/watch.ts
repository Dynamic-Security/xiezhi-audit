// Knowledge directory watching: recursive fs.watch, events debounced 300 ms and
// delivered as one batch of changed layers. Hidden paths (drafts, temp files of atomic writes) are
// ignored except `_settings.json`. Consumers rescan the layer: scanning is cheap and makes a burst of
// events (git checkout) a single reconciliation.
import { existsSync, mkdirSync, watch, type FSWatcher } from 'node:fs';
import { sep } from 'node:path';

export const WATCH_DEBOUNCE_MS = 300;

export interface KnowledgeChange {
  layer: 'global' | 'project';
  projectId: string | null;
}

export interface KnowledgeWatcher {
  close(): void;
  /** False when recursive watching is unavailable; changes are then only seen through the API. */
  active: boolean;
}

/**
 * Watch the global layer and every project's `knowledge/` under the projects root
 * (`<projects>/<pid>/knowledge/…`).
 */
export function watchKnowledge(globalDir: string, projectsDir: string, onChange: (changes: KnowledgeChange[]) => void, debounceMs = WATCH_DEBOUNCE_MS): KnowledgeWatcher {
  const pending = new Map<string, KnowledgeChange>();
  let timer: NodeJS.Timeout | null = null;
  const flush = () => {
    timer = null;
    const batch = [...pending.values()];
    pending.clear();
    if (batch.length) onChange(batch);
  };
  const push = (c: KnowledgeChange) => {
    pending.set(`${c.layer}:${c.projectId ?? ''}`, c);
    if (timer) clearTimeout(timer);
    timer = setTimeout(flush, debounceMs);
  };
  const relevant = (rel: string) => {
    const segs = rel.split(/[\\/]/).filter(Boolean);
    return segs.every((s) => !s.startsWith('.') && (!s.startsWith('_') || s === '_settings.json'));
  };
  const watchers: FSWatcher[] = [];
  let active = true;
  const start = (dir: string, handler: (rel: string) => void) => {
    try {
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      const w = watch(dir, { recursive: true }, (_evt, file) => { if (file) handler(String(file)); });
      w.on('error', () => { active = false; });
      watchers.push(w);
    } catch {
      active = false;
    }
  };
  start(globalDir, (rel) => { if (relevant(rel)) push({ layer: 'global', projectId: null }); });
  start(projectsDir, (rel) => {
    const segs = rel.split(sep).length > 1 ? rel.split(sep) : rel.split('/');
    if (segs.length < 3 || segs[1] !== 'knowledge') return;
    if (relevant(segs.slice(2).join('/'))) push({ layer: 'project', projectId: segs[0]! });
  });
  return {
    get active() { return active; },
    close() {
      if (timer) clearTimeout(timer);
      for (const w of watchers) w.close();
    },
  };
}
