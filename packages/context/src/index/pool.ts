// Worker pool for tree-sitter parsing. Falls back to inline extraction when running from
// TypeScript sources (tests) or for small inputs.
import { existsSync } from 'node:fs';
import { availableParallelism } from 'node:os';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';
import { Extractor } from './extract.js';
import type { RuleDef } from './rules.js';
import type { ExtractInput, FileExtract } from './types.js';

const INLINE_THRESHOLD = 40;

export function defaultWorkerCount(): number {
  return Math.max(1, Math.min(availableParallelism() - 1, 4));
}

export async function extractAll(inputs: ExtractInput[], rules: RuleDef[], opts: { workers?: number; signal?: AbortSignal } = {}): Promise<FileExtract[]> {
  const workerFile = fileURLToPath(new URL('./worker.js', import.meta.url));
  const canUseWorkers = import.meta.url.endsWith('.js') && existsSync(workerFile);
  const count = Math.min(opts.workers ?? defaultWorkerCount(), Math.ceil(inputs.length / 10));
  if (!canUseWorkers || inputs.length < INLINE_THRESHOLD || count <= 1) {
    const ex = new Extractor(rules);
    const out: FileExtract[] = [];
    for (const input of inputs) {
      if (opts.signal?.aborted) throw new Error('cancelled');
      out.push(await ex.extract(input));
    }
    return out;
  }
  const results: FileExtract[] = new Array(inputs.length);
  let next = 0;
  const workers = Array.from({ length: count }, () => new Worker(workerFile, {
    workerData: { rules },
    resourceLimits: { maxOldGenerationSizeMb: 1024 },
  }));
  try {
    await Promise.all(workers.map((w) => new Promise<void>((resolve, reject) => {
      const feed = () => {
        if (opts.signal?.aborted) { reject(new Error('cancelled')); return; }
        if (next >= inputs.length) { resolve(); return; }
        const id = next++;
        w.postMessage({ id, input: inputs[id] });
      };
      w.on('message', (msg: { id: number; result?: FileExtract; error?: string }) => {
        const input = inputs[msg.id]!;
        results[msg.id] = msg.result ?? {
          path: input.path, lang: input.lang, symbols: [], calls: [], entries: [], sinks: [], authSignals: [], pkg: '',
          gaps: [{ path: input.path, reason: 'parse_error', detail: msg.error ?? 'worker error' }],
        };
        feed();
      });
      w.on('error', reject);
      feed();
    })));
  } finally {
    await Promise.all(workers.map((w) => w.terminate()));
  }
  return results;
}
