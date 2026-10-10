// Add / edit a model provider: probe the service's models and pick them from a searchable list
// (manual IDs still possible), check the address, key and each picked model before saving; saving is not blocked
// by an unchecked or failed check, only flagged.
import { useEffect, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { ProviderCheckResult, ProviderDto, ProviderProbeResult } from '@xiezhi/contracts';
import { api, ApiError } from '../../shared/api/client';
import { Badge, Button, Dialog, Field, Icon, cx, ui, useToast } from '../../shared/ui';
import S from './settings.module.css';

/** A provider holds at most this many models (ProviderCreate / ProviderPatch). */
const MAX_MODELS = 100;
type ModelEntry = ProviderDto['models'][number];
type CheckState = { at: string; result: ProviderCheckResult } | null;

function ModelPicker({ selected, setSelected, configured, discovered, check }: {
  selected: string[]; setSelected: (ids: string[]) => void; configured: string[]; discovered: string[] | null;
  check: CheckState;
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
              <label className={cx(S.pickerItem, on && S.pickerOn)}>
                <input type="checkbox" checked={on} disabled={!on && full} onChange={() => toggle(id)} />
                <span className={cx(ui.mono, S.pickerId)}>{id}</span>
                {isNew && <Badge tone="accent">新</Badge>}
                {missing && <Badge tone="warn">服务端未列出</Badge>}
                {r && <Badge tone={r.ok ? 'ok' : 'danger'}>{r.ok ? `可用 · ${r.ms} ms` : '不可用'}</Badge>}
              </label>
              {r && !r.ok && <div className={S.pickerErr}>{r.detail}</div>}
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
      if (r.ok) setDiscovered(r.models);
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
    setSelected(existing?.models.map((m) => m.id) ?? []); setDiscovered(null); setProbe(null); setCheck(null); setErr(null);
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
    const list = selected.map((m) => keep.get(m) ?? { id: m });
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
        <ModelPicker key={open ? existing?.id ?? 'new' : 'closed'} selected={selected} setSelected={setSelected} configured={configured} discovered={discovered} check={check} />
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
