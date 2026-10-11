// Connector pack management: packs live in `<data-dir>/connectors/<name>/` as plain files.
// Built-in examples (repository `connector-packs/`) are installed on request. Packs drafted by AI from an
// OpenAPI document land in `.drafts/<id>/` and become packs only after review; AI never writes scripts.
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { AppError, ConnectorPackSubmit, newId, sha256Hex, type ModelRef, resourcePath } from '@xiezhi/contracts';
import { boundaryDeclaration, newNonce, startSession, wrapUntrusted, type AuditTool, type ModelHub } from '@xiezhi/agent';
import { PackError, PACK_NAME, loadPack, packScriptsHash, type Pack } from '@xiezhi/connectors';
import { atomicWrite } from '@xiezhi/knowledge';
import type { Store } from '@xiezhi/store';
import { stringify as toYaml } from 'yaml';
import { chatModelOf } from './services.js';
import { P } from '@xiezhi/knowledge';
import { withLivePrompts } from './prompts.js';

export function builtinPacksDir(): string {
  return resourcePath('connector-packs');
}

export function packDir(store: Store, name: string): string {
  if (!PACK_NAME.test(name)) throw new AppError('COMMON_VALIDATION', 'invalid pack name');
  return join(store.paths.connectorPacks, name);
}

export interface PackSummary {
  name: string; valid: boolean; errors: string[]; description: string | null; hash: string | null;
  operations: { name: string; kind: 'read' | 'write' }[]; scripts: string[]; interpreter: string | null; secrets: string[]; baseUrl: string | null;
}

export function summarizePack(dir: string, name: string): PackSummary {
  try {
    const p = loadPack(dir, name);
    return { name, valid: true, errors: [], description: p.description, hash: p.hash, operations: p.operations.map((o) => ({ name: o.name, kind: o.kind })), scripts: p.scripts, interpreter: p.interpreter, secrets: p.secrets, baseUrl: p.baseUrl };
  } catch (e) {
    return { name, valid: false, errors: e instanceof PackError ? e.errors : [(e as Error).message], description: null, hash: null, operations: [], scripts: [], interpreter: null, secrets: [], baseUrl: null };
  }
}

export function listPacks(store: Store): PackSummary[] {
  const root = store.paths.connectorPacks;
  if (!existsSync(root)) return [];
  return readdirSync(root).filter((n) => !n.startsWith('.') && !n.startsWith('_') && statSync(join(root, n)).isDirectory()).sort().map((n) => summarizePack(join(root, n), n));
}

export function listExamplePacks(): PackSummary[] {
  const root = builtinPacksDir();
  if (!existsSync(root)) return [];
  return readdirSync(root).filter((n) => statSync(join(root, n)).isDirectory()).sort().map((n) => summarizePack(join(root, n), n));
}

/** Copy a built-in example into the data-dir (never overwrites an existing pack). */
export function installExamplePack(store: Store, name: string): PackSummary {
  const src = join(builtinPacksDir(), name);
  if (!PACK_NAME.test(name) || !existsSync(src)) throw new AppError('COMMON_NOT_FOUND', `example pack ${name}`);
  const dst = packDir(store, name);
  if (existsSync(dst)) throw new AppError('COMMON_VALIDATION', `pack ${name} already exists`);
  mkdirSync(store.paths.connectorPacks, { recursive: true });
  cpSync(src, dst, { recursive: true });
  return summarizePack(dst, name);
}

function files(dir: string): string[] {
  const out: string[] = [];
  const rec = (d: string) => {
    for (const n of readdirSync(d).sort()) {
      if (n.startsWith('.') || n.startsWith('_')) continue;
      const p = join(d, n);
      if (statSync(p).isDirectory()) rec(p); else out.push(relative(dir, p).split(sep).join('/'));
    }
  };
  rec(dir);
  return out;
}

export function readPackFiles(store: Store, name: string): { path: string; text: string; sha256: string }[] {
  const dir = packDir(store, name);
  if (!existsSync(dir)) throw new AppError('COMMON_NOT_FOUND', `pack ${name}`);
  return files(dir).map((path) => {
    const text = readFileSync(join(dir, ...path.split('/')), 'utf8');
    return { path, text, sha256: sha256Hex(text) };
  });
}

const EDITABLE = /^(CONNECTOR\.md|operations\.yaml|scripts\/[A-Za-z0-9_.-]+\.(mjs|js|cjs|py))$/;

/** Edit one file with content-hash concurrency (same rule as knowledge edits). */
export function writePackFile(store: Store, name: string, path: string, text: string, base: string | null): PackSummary {
  if (!EDITABLE.test(path)) throw new AppError('COMMON_VALIDATION', 'only CONNECTOR.md, operations.yaml and scripts/*.{mjs,js,cjs,py} can be edited');
  const dir = packDir(store, name);
  const target = join(dir, ...path.split('/'));
  const cur = existsSync(target) ? sha256Hex(readFileSync(target, 'utf8')) : null;
  if (cur !== base) throw new AppError('COMMON_REVISION_CONFLICT', 'the file changed on disk');
  atomicWrite(target, text);
  return summarizePack(dir, name);
}

export function deletePack(store: Store, name: string): void {
  const dir = packDir(store, name);
  if (store.get('SELECT 1 FROM connector WHERE json_extract(config, \'$.pack\') = ?', name)) throw new AppError('COMMON_VALIDATION', `pack ${name} is used by a connector; delete the connector first`);
  rmSync(dir, { recursive: true, force: true });
}

/** Load a pack and the hash to confirm for its scripts with the given interpreter (null without scripts). */
export function packForConnector(store: Store, name: string, interpreterPath: string | null): { pack: Pack; scriptsHash: string | null } {
  const pack = loadPack(packDir(store, name), name);
  return { pack, scriptsHash: pack.scripts.length ? (interpreterPath ? packScriptsHash(pack, interpreterPath) : null) : null };
}

// ---- AI drafts from OpenAPI -------------------------------------------------------------------------------

export interface PackDraftRow { id: string; status: 'organizing' | 'ready' | 'failed' | 'approved' | 'rejected'; name: string | null; error: string | null; model: string | null; tokens: number; createdAt: number; files: string[]; errors: string[] }

const draftRoot = (store: Store) => join(store.paths.connectorPacks, '.drafts');

/** Write a pack draft's metadata (also used to settle drafts a restart cut off). */
export function savePackDraft(store: Store, d: PackDraftRow): void {
  atomicWrite(join(draftRoot(store), d.id, 'draft.json'), `${JSON.stringify(d, null, 1)}\n`);
}

export function getPackDraft(store: Store, id: string): PackDraftRow {
  if (!/^kdr_[0-9A-Z]{26}$/.test(id)) throw new AppError('COMMON_NOT_FOUND', 'pack draft');
  try { return JSON.parse(readFileSync(join(draftRoot(store), id, 'draft.json'), 'utf8')) as PackDraftRow; } catch { throw new AppError('COMMON_NOT_FOUND', 'pack draft'); }
}

export function listPackDrafts(store: Store): PackDraftRow[] {
  const root = draftRoot(store);
  if (!existsSync(root)) return [];
  return readdirSync(root).flatMap((id) => { try { return [getPackDraft(store, id)]; } catch { return []; } }).filter((d) => d.status !== 'approved' && d.status !== 'rejected').sort((a, b) => b.createdAt - a.createdAt);
}

export function readPackDraftFiles(store: Store, id: string): { path: string; text: string }[] {
  getPackDraft(store, id);
  const dir = join(draftRoot(store), id, 'pack');
  return existsSync(dir) ? files(dir).map((path) => ({ path, text: readFileSync(join(dir, ...path.split('/')), 'utf8') })) : [];
}

export function createPackDraft(store: Store, input: { openapi: string; name?: string; focus?: string }): PackDraftRow {
  if (!input.openapi.trim()) throw new AppError('COMMON_VALIDATION', 'openapi text is empty');
  if (input.openapi.length > 500_000) throw new AppError('COMMON_VALIDATION', 'openapi document exceeds 500 000 characters');
  const d: PackDraftRow = { id: newId('knowledgeDraft'), status: 'organizing', name: input.name ?? null, error: null, model: null, tokens: 0, createdAt: Date.now(), files: [], errors: [] };
  mkdirSync(join(draftRoot(store), d.id), { recursive: true });
  atomicWrite(join(draftRoot(store), d.id, 'input.json'), JSON.stringify(input));
  savePackDraft(store, d);
  return d;
}

/** Organize a draft with the chat model and write the pack files (CONNECTOR.md + operations.yaml). */
async function processPackDraftInner(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  const { store } = deps;
  const d = getPackDraft(store, id);
  const usage = { total: 0 };
  try {
    let model: ModelRef;
    try { model = chatModelOf(store.config); } catch { throw new AppError('MODEL_NOT_CONFIGURED', 'pack drafting needs a chat or default model'); }
    const input = JSON.parse(readFileSync(join(draftRoot(store), id, 'input.json'), 'utf8')) as { openapi: string; name?: string; focus?: string };
    const nonce = newNonce();
    const tool: AuditTool = { name: 'submit_connector_pack', kind: 'submit', parameters: ConnectorPackSubmit, description: P('tool.submit_connector_pack'), run: () => ({ text: 'recorded' }) };
    const outcome = await startSession({
      hub: deps.hub, model, cwd: store.paths.tmp, agentDir: store.paths.agent,
      systemPrompt: [P('role.pack_author'), boundaryDeclaration(nonce)].join('\n\n'),
      prompt: [P('packs.guide'), '', `包名建议：${input.name ?? '（按系统名）'}${input.focus ? `；用途：${input.focus}` : ''}`, wrapUntrusted(nonce, 'user_upload', 'openapi', input.openapi.slice(0, 400_000))].join('\n'),
      tools: [tool], requiredSubmits: ['submit_connector_pack'], maxTurns: 4, signal,
      onUsage: (u) => { usage.total += u.total; return 'continue'; },
    }).outcome;
    const sub = (outcome.submissions.submit_connector_pack as ConnectorPackSubmit[] | undefined)?.at(-1);
    if (!sub) throw new Error(`the model did not submit (${outcome.status}${outcome.errorMessage ? `: ${outcome.errorMessage.slice(0, 200)}` : ''})`);
    const name = input.name ?? sub.name;
    const dir = join(draftRoot(store), id, 'pack');
    rmSync(dir, { recursive: true, force: true });
    const auth = sub.auth.type === 'header' && sub.auth.value ? { type: 'header', name: sub.auth.header ?? 'Authorization', value: sub.auth.value } : { type: 'none' };
    atomicWrite(join(dir, 'CONNECTOR.md'), `---\n${toYaml({ name, description: sub.description, base_url: sub.baseUrl, auth, secrets: sub.secrets })}---\n# ${name}\n\n由 AI 根据 OpenAPI 文档生成，启用前请核对每个操作的读写标注、参数限制与返回字段。\n\n${sub.notes}\n`);
    const operations = sub.operations.map((o) => ({
      name: o.name, kind: o.kind, description: o.description, method: o.method, path: o.path,
      ...(o.query ? { query: o.query } : {}), ...(o.body !== undefined ? { body: o.body } : {}), params: o.params, ...(o.extract ? { response: { extract: o.extract } } : {}),
    }));
    atomicWrite(join(dir, 'operations.yaml'), `# generated from an OpenAPI document; review before use\n${toYaml({ operations })}`);
    let errors: string[] = [];
    try { loadPack(dir, name); } catch (e) { errors = e instanceof PackError ? e.errors : [(e as Error).message]; }
    savePackDraft(store, { ...d, status: 'ready', name, model: `${model.provider}/${model.model}`, tokens: usage.total, files: files(dir), errors });
  } catch (e) {
    savePackDraft(store, { ...d, status: 'failed', error: (e as Error).message.slice(0, 500), tokens: usage.total });
  }
}

/** Approve: the draft becomes `<data-dir>/connectors/<name>/` (must be valid; never overwrites). */
export function approvePackDraft(store: Store, id: string): PackSummary {
  const d = getPackDraft(store, id);
  if (d.status !== 'ready' || !d.name) throw new AppError('COMMON_VALIDATION', `pack draft is ${d.status}`);
  const src = join(draftRoot(store), id, 'pack');
  try { loadPack(src, d.name); } catch (e) { throw new AppError('COMMON_VALIDATION', (e as Error).message); }
  const dst = packDir(store, d.name);
  if (existsSync(dst)) throw new AppError('COMMON_VALIDATION', `pack ${d.name} already exists`);
  renameSync(src, dst);
  savePackDraft(store, { ...d, status: 'approved' });
  return summarizePack(dst, d.name);
}

export function rejectPackDraft(store: Store, id: string): void {
  const d = getPackDraft(store, id);
  savePackDraft(store, { ...d, status: 'rejected' });
}

/** connector packs are global — the global prompt overrides. */
export async function processPackDraft(deps: { store: Store; hub: ModelHub }, id: string, signal: AbortSignal): Promise<void> {
  return withLivePrompts(deps.store, null, () => processPackDraftInner(deps, id, signal), 'pack_draft', id);
}
