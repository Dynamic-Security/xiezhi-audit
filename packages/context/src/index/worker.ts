// worker_threads entry: holds one Extractor (grammars loaded once per thread).
import { parentPort, workerData } from 'node:worker_threads';
import { Extractor } from './extract.js';
import type { RuleDef } from './rules.js';
import type { ExtractInput } from './types.js';

const extractor = new Extractor((workerData as { rules: RuleDef[] }).rules);

parentPort!.on('message', async (msg: { id: number; input: ExtractInput }) => {
  try {
    const result = await extractor.extract(msg.input);
    parentPort!.postMessage({ id: msg.id, result });
  } catch (e) {
    parentPort!.postMessage({ id: msg.id, error: (e as Error).message });
  }
});
