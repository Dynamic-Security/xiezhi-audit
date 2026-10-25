// Add / edit a model provider: probe the service's models and pick them from a searchable list
// (manual IDs still possible), check the address, key and each picked model before saving; saving is not blocked
// by an unchecked or failed check, only flagged. Each picked model carries its context window and output cap: filled
// from the probe when the service lists them, editable by hand (the server registers 128k / 8192 otherwise), and
// whether it may receive facts marked confidential (stored in the global `confidentialModels`).
import { useEffect, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { ProviderCheckResult, ProviderDto, ProviderProbeResult } from '@xiezhi/contracts';
import { api, ApiError } from '../../shared/api/client';
import { Badge, Button, Dialog, Field, Icon, InfoTip, cx, ui, useToast } from '../../shared/ui';
import S from './settings.module.css';

/** A provider holds at most this many models (ProviderCreate / ProviderPatch). */
const MAX_MODELS = 100;
type ModelEntry = ProviderDto['models'][number];
type CheckState = { at: string; result: ProviderCheckResult } | null;
/** `images: false` makes the model text only (conversation attachments); unset means it takes images. */
type Limits = { contextWindow?: number; maxTokens?: number; images?: boolean };
type LimitsMap = Record<string, Limits>;

/** What “可接收机密事实” means; shown behind the ⓘ next to the tag and on provider cards. */
export const CONFIDENTIAL_HELP = '开启后，标为“机密”的企业事实可以发给这个模型（例如内网部署的模型）。未开启的模型的会话里不出现这些事实，外发记录中计为“未发送的机密事实”。';

/** A token count typed by hand: digits, optionally with k (thousand) or m (million); empty or invalid clears it. */
function parseTokens(raw: string): number | undefined {
  const m = /^\s*(\d+(?:\.\d+)?)\s*([km]?)\s*$/i.exec(raw);
  if (!m) return undefined;
  const n = Math.round(Number(m[1]) * (m[2]!.toLowerCase() === 'k' ? 1000 : m[2]!.toLowerCase() === 'm' ? 1_000_000 : 1));
  return n > 0 ? n : undefined;
}

function LimitInput({ label, value, min, onChange }: { label: string; value: number | undefined; min: number; onChange: (v: number | undefined) => void }) {
  const [text, setText] = useState(value ? String(value) : '');
  useEffect(() => { setText(value ? String(value) : ''); }, [value]);
  const parsed = parseTokens(text);
  const bad = !!text.trim() && (parsed === undefined || parsed < min);
  return (
    <label className={S.limitField}>
      <span>{label}</span>
      <input className={cx(ui.input, ui.mono, bad && S.limitBad)} inputMode="numeric" placeholder="未设置" value={text} title={bad ? `至少 ${min}` : undefined}
        onChange={(e) => setText(e.target.value)} onBlur={() => { const v = parseTokens(text); onChange(v !== undefined && v >= min ? v : undefined); }} />
    </label>
  );
}

function ModelPicker({ selected, setSelected, configured, discovered, check, limits, setLimits, confidential, setConfidential }: {
  selected: string[]; setSelected: (ids: string[]) => void; configured: string[]; discovered: string[] | null;
  check: CheckState; limits: LimitsMap; setLimits: (id: string, l: Limits) => void;
  confidential: string[]; setConfidential: (f: (ids: string[]) => string[]) => void;
}) {
  const [q, setQ] = useState('');
  const [manual, setManual] = useState('');
  /** IDs added by hand stay listed when unchecked (a misclick must not lose them). */
  const [added, setAdded] = useState<string[]>([]);
  const all = useMemo(() => [...new Set([...selected, ...configured, ...(discovered ?? []), ...added])], [selected, configured, discovered, added]);
  const shown = all.filter((id) => id.toLowerCase().includes(q.trim().toLowerCase()));
  const full = selected.length >= MAX_MODELS;
  const byCheck = new Map((check?.result.models ?? []).map((m) => [m.id, m]));
  const toggle = (id: string) => setSelected(selected.includes(id) ? selected.filter((x) => x !== id) : [...selected, id]);
  const addManual = () => {
    const ids = manual.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
    setSelected([...new Set([...selected, ...ids])].slice(0, MAX_MODELS));
    setAdded([...new Set([...added, ...ids])]);
    setManual('');
  };
  return (
    <div className={S.picker}>
      <div className={S.pickerHead}>
        <span>已选 <b>{selected.length}</b>{discovered ? ` / 服务端列出 ${discovered.length}` : ''}</span>
        <div className={S.pickerSearch}><Icon name="search" size={13} /><input aria-label="搜索模型" placeholder="搜索模型…" value={q} onChange={(e) => setQ(e.target.value)} /></div>
        <button className={S.linkBtn} disabled={!shown.length} onClick={() => setSelected([...new Set([...selected, ...shown])].slice(0, MAX_MODELS))}>全选当前结果</button>
        <button className={S.linkBtn} disabled={!selected.length} onClick={() => setSelected([])}>清空</button>
      </div>
      {full && <div className={S.pickerNote}>一个服务最多 {MAX_MODELS} 个模型，已达上限。</div>}
      <ul className={S.pickerList} aria-label="模型列表">
        {!all.length && <li className={S.pickerEmpty}>点“探测可用模型”列出服务端的模型，或在下方手动添加模型 ID。</li>}
        {all.length > 0 && !shown.length && <li className={S.pickerEmpty}>没有匹配“{q}”的模型。</li>}
        {shown.map((id) => {
          const on = selected.includes(id);
          const isNew = !!discovered && discovered.includes(id) && !configured.includes(id);
          const missing = !!discovered && configured.includes(id) && !discovered.includes(id);
          const r = byCheck.get(id);
          return (
            <li key={id}>
              <div className={cx(S.pickerRow, on && S.pickerOn)}>
                <label className={S.pickerItem}>
                  <input type="checkbox" checked={on} disabled={!on && full} onChange={() => toggle(id)} />
                  <span className={cx(ui.mono, S.pickerId)}>{id}</span>
                  {isNew && <Badge tone="accent">新</Badge>}
                  {missing && <Badge tone="warn">服务端未列出</Badge>}
                  {r && <Badge tone={r.ok ? 'ok' : 'danger'}>{r.ok ? `可用 · ${r.ms} ms` : '不可用'}</Badge>}
                </label>
                {on && (
                  <span className={S.confWrap}>
                    <button type="button" className={cx(S.confTag, confidential.includes(id) && S.confOn)} aria-pressed={confidential.includes(id)} aria-label={`可接收机密事实 ${id}`}
                      onClick={() => setConfidential((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]))}>
                      <Icon name="lock" size={12} />{confidential.includes(id) ? '可接收机密' : '不接收机密'}
                    </button>
                    <InfoTip label="可接收机密事实的含义">{CONFIDENTIAL_HELP}</InfoTip>
                  </span>
                )}
              </div>
              {r && !r.ok && <div className={S.pickerErr}>{r.detail}</div>}
              {on && (
                <div className={S.limits}>
                  <LimitInput label="上下文窗口" min={1024} value={limits[id]?.contextWindow} onChange={(v) => setLimits(id, { ...limits[id], contextWindow: v })} />
                  <LimitInput label="最大输出" min={256} value={limits[id]?.maxTokens} onChange={(v) => setLimits(id, { ...limits[id], maxTokens: v })} />
                  <label className={S.limitCheck} title="关闭后，会话中不能向这个模型发送图片">
                    <input type="checkbox" checked={limits[id]?.images !== false} onChange={(e) => setLimits(id, { ...limits[id], images: e.target.checked ? undefined : false })} />
                    <span>支持图片</span>
                  </label>
                  {!limits[id]?.contextWindow && <span className={S.limitHint}>未设置时按 128k 上下文、8192 输出处理</span>}
                </div>
              )}
            </li>
          );
        })}
      </ul>
      <div className={S.pickerManual}>
        <input className={cx(ui.input, ui.mono)} aria-label="手动添加模型 ID" placeholder="手动添加模型 ID（服务不提供模型列表时使用）" value={manual}
          onChange={(e) => setManual(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter' && !e.nativeEvent.isComposing && manual.trim()) { e.preventDefault(); addManual(); } }} />
        <Button size="sm" icon="plus" disabled={!manual.trim() || full} onClick={addManual}>添加</Button>
      </div>
    </div>
  );
}

export function ProviderDialog({ open, onClose, existing, autoProbe }: { open: boolean; onClose: () => void; existing: ProviderDto | null; autoProbe?: boolean }) {
  const [id, setId] = useState('');
  const [apiKind, setApiKind] = useState('openai-completions');
  const [baseUrl, setBaseUrl] = useState('');
  const [key, setKey] = useState('');
  const [selected, setSelected] = useState<string[]>([]);
  const [discovered, setDiscovered] = useState<string[] | null>(null);
  /** Context window / output cap per model: the saved values, then what a probe reports for models without one. */
  const [limits, setLimitsMap] = useState<LimitsMap>({});
  const [confidential, setConfidential] = useState<string[]>([]);
  const setLimits = (mid: string, l: Limits) => setLimitsMap((cur) => ({ ...cur, [mid]: l }));
  const [probe, setProbe] = useState<{ ok: boolean; detail: string } | null>(null);
  const [check, setCheck] = useState<CheckState>(null);
  const [busy, setBusy] = useState<'save' | 'probe' | 'check' | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const configured = useMemo(() => existing?.models.map((m) => m.id) ?? [], [existing]);
  const form = () => ({ ...(existing ? { id: existing.id } : {}), api: apiKind, baseUrl, ...(key ? { apiKey: key } : {}) });

  /** `body` defaults to the form; the auto-probe passes the saved provider (the form state is not set yet then). */
  const runProbe = async (body: Record<string, unknown> = form()) => {
    setBusy('probe');
    setErr(null);
    try {
      const r = await api.post<ProviderProbeResult>('/settings/model-providers/probe', body);
      setProbe({ ok: r.ok, detail: r.detail });
      if (r.ok) {
        setDiscovered(r.models);
        // a value already set (saved or typed) is kept; the probe fills only what is missing.
        setLimitsMap((cur) => {
          const next = { ...cur };
          for (const [mid, l] of Object.entries(r.limits ?? {})) next[mid] = { ...cur[mid], contextWindow: cur[mid]?.contextWindow ?? l.contextWindow, maxTokens: cur[mid]?.maxTokens ?? l.maxTokens };
          return next;
        });
      }
    } catch (e) { setErr(e instanceof ApiError ? `${e.message}${e.hint ? `：${e.hint}` : ''}` : String(e)); }
    setBusy(null);
  };
  const runCheck = async () => {
    setBusy('check');
    setErr(null);
    try {
      const r = await api.post<ProviderCheckResult>('/settings/model-providers/check', { ...form(), models: selected });
      setCheck({ at: new Date().toISOString(), result: r });
    } catch (e) { setErr(e instanceof ApiError ? `${e.message}${e.hint ? `：${e.hint}` : ''}` : String(e)); }
    setBusy(null);
  };

  useEffect(() => {
    if (!open) return;
    setId(existing?.id ?? ''); setApiKind(existing?.api ?? 'openai-completions'); setBaseUrl(existing?.baseUrl ?? ''); setKey('');
    setSelected(existing?.models.map((m) => m.id) ?? []); setDiscovered(null); setProbe(null);
    setLimitsMap(Object.fromEntries((existing?.models ?? []).map((m) => [m.id, { contextWindow: m.contextWindow, maxTokens: m.maxTokens, ...(m.images === false ? { images: false } : {}) }]))); setCheck(null); setErr(null);
    setConfidential((existing?.models ?? []).filter((m) => m.confidential).map((m) => m.id));
  }, [open, existing]);
  // Opened from a provider card's “探测可用模型”: probe with the saved key at once.
  useEffect(() => {
    if (open && autoProbe && existing) void runProbe({ id: existing.id, api: existing.api, baseUrl: existing.baseUrl });
  }, [open, autoProbe, existing]);
  // A changed address, protocol or key makes an earlier check stale.
  useEffect(() => { setCheck(null); }, [apiKind, baseUrl, key]);

  const originChanged = (() => { try { return !!existing && new URL(baseUrl).origin !== new URL(existing.baseUrl).origin; } catch { return false; } })();
  const untested = check ? selected.filter((m) => !check.result.models.some((r) => r.id === m)).length : selected.length;
  const failed = check ? check.result.models.filter((r) => !r.ok && selected.includes(r.id)).length : 0;
  const saveNote = !check ? '尚未测验连通性，仍可保存'
    : !check.result.list.ok && !check.result.models.some((r) => r.ok) ? '连通性测验未通过，仍可保存'
      : failed ? `${failed} 个模型测验不可用，仍可保存`
        : untested ? `${untested} 个模型未测验` : '';

  const save = async () => {
    setBusy('save');
    setErr(null);
    // Keep what is already known about a model (name, context window…); new picks are plain IDs.
    const keep = new Map<string, ModelEntry>((existing?.models ?? []).map((m) => [m.id, m]));
    const list = selected.map((m) => {
      const { contextWindow: _c, maxTokens: _t, confidential: _s, images: _i, ...base } = keep.get(m) ?? { id: m };
      const l = limits[m];
      return { ...base, ...(l?.contextWindow ? { contextWindow: l.contextWindow } : {}), ...(l?.maxTokens ? { maxTokens: l.maxTokens } : {}), ...(l?.images === false ? { images: false } : {}), ...(confidential.includes(m) ? { confidential: true } : {}) };
    });
    try {
      if (existing) {
        const r = await api.patch<ProviderDto & { keyCleared?: boolean }>(`/settings/model-providers/${existing.id}`, { api: apiKind, baseUrl, models: list, ...(key ? { apiKey: key } : {}) });
        toast.ok(r.keyCleared ? '已保存；服务地址已变更，原密钥已清除，请重新填写' : '已保存');
      } else {
        await api.post('/settings/model-providers', { id, api: apiKind, baseUrl, models: list, ...(key ? { apiKey: key } : {}) });
        toast.ok('已添加模型服务');
      }
      setKey('');
      await qc.invalidateQueries({ queryKey: ['settings'] });
      onClose();
    } catch (e) {
      setErr(e instanceof ApiError ? `${e.message}${e.hint ? `：${e.hint}` : ''}` : String(e));
    }
    setBusy(null);
  };

  return (
    <Dialog open={open} onClose={onClose} wide title={existing ? `编辑模型服务 · ${existing.id}` : '添加模型服务'} footer={<>
      <Button icon="search" loading={busy === 'probe'} disabled={!baseUrl || !!busy} onClick={() => void runProbe()}>探测可用模型</Button>
      <Button icon="activity" loading={busy === 'check'} disabled={!baseUrl || !!busy} onClick={() => void runCheck()}>测验连通性</Button>
      <span className={ui.grow} />
      {saveNote && <span className={S.saveNote}>{saveNote}</span>}
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy === 'save'} disabled={!baseUrl || !selected.length || (!existing && !id) || (!!busy && busy !== 'save')} onClick={() => void save()}>保存</Button>
    </>}>
      {!existing && <Field label="服务 ID" hint="小写字母、数字、- 或 _，例如 gateway"><input className={ui.input} value={id} onChange={(e) => setId(e.target.value)} autoFocus /></Field>}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 12 }}>
        <Field label="协议"><select className={ui.select} value={apiKind} onChange={(e) => setApiKind(e.target.value)}>
          <option value="openai-completions">OpenAI Chat Completions</option><option value="openai-responses">OpenAI Responses</option><option value="anthropic-messages">Anthropic Messages</option>
        </select></Field>
        <Field label="服务地址（baseUrl）"><input className={cx(ui.input, ui.mono)} value={baseUrl} placeholder="https://api.example.com/v1" onChange={(e) => setBaseUrl(e.target.value)} /></Field>
      </div>
      <Field label="API 密钥" hint={existing?.apiKey.configured ? `已配置${existing.apiKey.hint ? `（${existing.apiKey.hint}）` : ''}；留空表示保持不变，探测与测验也使用已保存的密钥` : '只保存在本机配置文件（权限 0600），界面不会回显'}>
        <input className={cx(ui.input, ui.mono)} type="password" autoComplete="new-password" value={key} placeholder={existing?.apiKey.configured ? '••••••••（保持不变）' : ''} onChange={(e) => setKey(e.target.value)} />
      </Field>
      {originChanged && !key && <div className={ui.banner} style={{ background: 'var(--warn-soft)', color: 'var(--warn)' }}><Icon name="alert" />服务地址的来源（origin）已变更：密钥与地址绑定，探测与测验不会带上原密钥，保存后原密钥会被清除。</div>}
      <Field label="模型" hint="勾选要使用的模型；按服务端命名，例如 openai/gpt-6-luna">
        <ModelPicker key={open ? existing?.id ?? 'new' : 'closed'} selected={selected} setSelected={setSelected} configured={configured} discovered={discovered} check={check} limits={limits} setLimits={setLimits} confidential={confidential} setConfidential={setConfidential} />
      </Field>
      {probe && <div className={cx(S.result, probe.ok ? S.resultOk : S.resultBad)} role="status"><Icon name={probe.ok ? 'check' : 'alert'} size={13} />探测：{probe.detail}</div>}
      {check && (
        <div className={cx(S.result, check.result.ok ? S.resultOk : S.resultBad)} role="status">
          <Icon name={check.result.ok ? 'checkCircle' : 'alert'} size={13} />
          测验连通性：{check.result.detail}
          {check.result.models.length > 0 && !check.result.list.ok && <span className={ui.faint}>（服务不提供模型列表不影响使用）</span>}
          {check.result.truncated && <span className={ui.faint}>；一次最多测验 10 个模型，其余未测验</span>}
        </div>
      )}
      {err && <div className={ui.error}>{err}</div>}
    </Dialog>
  );
}
