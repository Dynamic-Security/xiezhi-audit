// Settings › 连接器: MCP connectors over stdio or streamable HTTP.
// Credentials are `${secret:name}` references with write-only values; a stdio command runs only after the
// user confirmed the exact command line; MCP connectors offer every tool to the Agent (calls carrying
// instructions from the audited code wait for approval), connector packs offer the read operations chosen here;
// any configuration change requires a new connectivity test.
import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { ConnectorDto, ConnectorPackDraftDto, ConnectorPackDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { useConnectors } from '../../shared/api/queries';
import { fmt } from '../../shared/format/messages';
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, Field, Loading, cx, ui, useToast } from '../../shared/ui';
import { Section } from '../layout/AppShell';
import S from './settings.module.css';
import { ImportMcpDialog } from './ImportMcp';

const STATUS: Record<string, { l: string; t: 'ok' | 'warn' | 'danger' | 'neutral' }> = {
  ready: { l: '可用', t: 'ok' }, untested: { l: '未测试', t: 'warn' }, failed: { l: '测试失败', t: 'danger' }, needs_confirmation: { l: '需要确认命令', t: 'warn' },
};


const lines = (t: string) => t.split('\n').map((l) => l.trim()).filter(Boolean);
function pairs(t: string, sep: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const l of lines(t)) {
    const i = l.indexOf(sep);
    if (i > 0) out[l.slice(0, i).trim()] = l.slice(i + 1).trim();
  }
  return out;
}
const unpairs = (r: Record<string, string> | undefined, sep: string) => Object.entries(r ?? {}).map(([k, v]) => `${k}${sep}${v}`).join('\n');

/** `kind`: an MCP connector, or a connector that calls a pack directly (command line or HTTP API). */
function ConnectorDialog({ open, onClose, existing, kind, presetPack }: { open: boolean; onClose: () => void; existing: ConnectorDto | null; kind: 'mcp' | 'pack'; presetPack?: string | null }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState('');
  const [protocol, setProtocol] = useState<'mcp_stdio' | 'mcp_http' | 'http'>('mcp_http');
  const [pack, setPack] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [vars, setVars] = useState('');
  const [interp, setInterp] = useState('');
  const [prog, setProg] = useState('');
  const packs = useQuery({ queryKey: ['connector-packs'], enabled: open, queryFn: () => api.get<ConnectorPackDto[]>('/connector-packs') });
  const [path, setPath] = useState('');
  const [args, setArgs] = useState('');
  const [env, setEnv] = useState('');
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState('');
  const [callSec, setCallSec] = useState(30);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!open) return;
    setErr(null);
    setName(existing?.name ?? '');
    setProtocol((existing?.protocol as 'mcp_stdio' | 'mcp_http' | 'http' | undefined) ?? (kind === 'pack' ? 'http' : 'mcp_http'));
    setPack(existing?.config.pack ?? presetPack ?? '');
    setBaseUrl(existing?.config.base_url ?? '');
    setVars(unpairs(existing?.config.variables, '='));
    setInterp(existing?.config.interpreter_path ?? '');
    setProg(existing?.config.program_path ?? '');
    setPath(existing?.config.command?.path ?? '');
    setArgs((existing?.config.command?.args ?? []).join('\n'));
    setEnv(unpairs(existing?.config.command?.env, '='));
    setUrl(existing?.config.url ?? '');
    setHeaders(unpairs(existing?.config.headers, ':'));
    setCallSec(Math.round((existing?.config.timeouts?.callMs ?? 30_000) / 1000));
  }, [open, existing, kind, presetPack]);
  const config = () => ({
    ...(protocol === 'mcp_stdio' ? { command: { path: path.trim(), args: lines(args), env: pairs(env, '=') } }
      : protocol === 'http' ? { pack: pack || packs.data?.[0]?.name, ...(baseUrl.trim() ? { base_url: baseUrl.trim() } : {}), ...(vars.trim() ? { variables: pairs(vars, '=') } : {}), ...(interp.trim() ? { interpreter_path: interp.trim() } : {}), ...(prog.trim() ? { program_path: prog.trim() } : {}) }
      : { url: url.trim(), headers: pairs(headers, ':') }),
    timeouts: { callMs: callSec * 1000 },
  });
  const save = async () => {
    setBusy(true);
    setErr(null);
    try {
      if (existing) await api.patch(`/connectors/${existing.id}`, { name, config: config() });
      else await api.post('/connectors', { name, protocol, config: config() });
      toast.ok(existing ? '已保存，需要重新测试' : '已添加');
      await qc.invalidateQueries({ queryKey: ['connectors'] });
      onClose();
    } catch (e) { setErr(e instanceof Error ? ((e as { hint?: string }).hint ?? e.message) : String(e)); } finally { setBusy(false); }
  };
  return (
    <Dialog open={open} onClose={onClose} wide title={existing ? `编辑连接器 ${existing.name}` : kind === 'pack' ? '用连接器包添加连接器' : '添加 MCP 连接器'} footer={<>
      {err && <div role="alert" className={ui.error} style={{ marginRight: 'auto', maxWidth: '65%' }}>{err}</div>}
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!name.trim()} onClick={() => void save()}>保存</Button>
    </>}>
      <p className={ui.muted} style={{ margin: 0 }}>{protocol === 'http' ? '按连接器包中声明的命令行命令或 HTTP 接口直接调用，不经过 MCP。' : '通过 MCP 服务接入工单、文档、CMDB 等系统。'}凭证不要直接写在配置里：写成 <code>{'${secret:名称}'}</code>，保存后在“密钥”中填写（只写不读，只保存在本机配置文件中）。</p>
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 12 }}>
        <Field label="名称"><input className={ui.input} value={name} onChange={(e) => setName(e.target.value)} autoFocus /></Field>
        {protocol !== 'http' && <Field label="传输"><select className={ui.input} value={protocol} disabled={!!existing} onChange={(e) => setProtocol(e.target.value as 'mcp_stdio' | 'mcp_http')}><option value="mcp_http">streamable HTTP</option><option value="mcp_stdio">本机命令（stdio）</option></select></Field>}
        
        <Field label="单次调用超时（秒）"><input className={ui.input} type="number" min={1} max={300} value={callSec} onChange={(e) => setCallSec(Number(e.target.value))} /></Field>
      </div>
      {protocol === 'http' ? (
        <>
          <Field label="连接器包" hint="在“连接器包”中安装示例或由 AI 从 OpenAPI 生成"><select className={ui.input} value={pack || packs.data?.[0]?.name || ''} onChange={(e) => setPack(e.target.value)}>{(packs.data ?? []).filter((p) => p.valid).map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}</select></Field>
          <Field label="站点地址（覆盖包里的 base_url）" hint="例如 https://acme.atlassian.net；只能访问这个主机"><input className={cx(ui.input, ui.mono)} value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} /></Field>
          <Field label="变量（每行 KEY=VALUE，非敏感）"><textarea className={cx(ui.textarea, ui.mono)} value={vars} onChange={(e) => setVars(e.target.value)} /></Field>
          <Field label="脚本解释器（绝对路径，可选）" hint="包里有脚本时使用；node 脚本默认用本服务的 Node"><input className={cx(ui.input, ui.mono)} value={interp} onChange={(e) => setInterp(e.target.value)} /></Field>
          <Field label="命令行程序（绝对路径，可选）" hint="包声明了命令行程序时使用（如 lark-cli）；不填则在 PATH 与常用安装目录中查找"><input className={cx(ui.input, ui.mono)} value={prog} onChange={(e) => setProg(e.target.value)} placeholder="/opt/homebrew/bin/lark-cli" /></Field>
        </>
      ) : protocol === 'mcp_stdio' ? (
        <>
          <Field label="命令（绝对路径）" hint="例如 /usr/local/bin/node；首次添加和每次修改后都需要确认完整命令行"><input className={cx(ui.input, ui.mono)} value={path} onChange={(e) => setPath(e.target.value)} /></Field>
          <Field label="参数（每行一个）"><textarea className={cx(ui.textarea, ui.mono)} value={args} onChange={(e) => setArgs(e.target.value)} /></Field>
          <Field label="环境变量（每行 KEY=VALUE）" hint="子进程不继承本服务的环境变量；凭证写成 ${secret:名称}"><textarea className={cx(ui.textarea, ui.mono)} value={env} onChange={(e) => setEnv(e.target.value)} /></Field>
        </>
      ) : (
        <>
          <Field label="地址" hint="只允许 https；内网主机可用 http。只能访问这里配置的主机，重定向不会被跟随"><input className={cx(ui.input, ui.mono)} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://mcp.example.com/mcp" /></Field>
          <Field label="请求头（每行 Name: value）" hint="例如 Authorization: Bearer ${secret:token}"><textarea className={cx(ui.textarea, ui.mono)} value={headers} onChange={(e) => setHeaders(e.target.value)} /></Field>
        </>
      )}
    </Dialog>
  );
}

function ConnectorCard({ c, onEdit }: { c: ConnectorDto; onEdit: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [secrets, setSecrets] = useState<Record<string, string>>({});
  // Optimistic exposure while the change is saved.
  const [exposure, setExposure] = useState<Record<string, boolean>>({});
  const [confirm, setConfirm] = useState(false);
  const [del, setDel] = useState(false);
  const [trust, setTrust] = useState(false);
  const mcp = c.protocol === 'mcp_http' || c.protocol === 'mcp_stdio';
  const [busy, setBusy] = useState<string | null>(null);
  const refresh = () => qc.invalidateQueries({ queryKey: ['connectors'] });
  const act = async (what: string, fn: () => Promise<unknown>, ok?: string) => {
    setBusy(what);
    try { await fn(); if (ok) toast.ok(ok); await refresh(); } catch (e) { toast.error(e); } finally { setBusy(null); }
  };
  const st = STATUS[c.status] ?? { l: c.status, t: 'neutral' as const };
  return (
    <div className={cx(ui.card, S.provider)} style={{ flexDirection: 'column', alignItems: 'stretch', gap: 10 }}>
      <div className={ui.spread}>
        <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
          <b>{c.name}</b><Badge tone={st.t}>{st.l}</Badge><Badge>{c.protocol === 'mcp_stdio' ? 'MCP stdio' : c.protocol === 'http' ? `连接器包 ${c.config.pack ?? ''}` : 'MCP HTTP'}</Badge>
          {!c.enabled && <Badge tone="neutral">已停用</Badge>}
          {c.authoritative && <Badge tone="accent" title="结果可直接作为判断依据">权威数据源</Badge>}
          {c.breaker.state !== 'closed' && <Badge tone="danger">熔断中（连续失败 {c.breaker.failures} 次）</Badge>}
        </div>
        <div className={ui.row}>
          <Button size="sm" loading={busy === 'test'} disabled={c.status === 'needs_confirmation'} onClick={() => void act('test', () => api.post(`/connectors/${c.id}/test`), undefined)}>测试连接</Button>
          <Button size="sm" onClick={() => void act('enable', () => api.patch(`/connectors/${c.id}`, { enabled: !c.enabled }))}>{c.enabled ? '停用' : '启用'}</Button>
          <Button size="sm" icon="edit" aria-label="编辑" onClick={onEdit} />
          <Button size="sm" variant="ghost" icon="trash" aria-label="删除" onClick={() => setDel(true)} />
        </div>
      </div>
      {(c.protocol === 'mcp_stdio' || c.protocol === 'http') && c.commandLine && (
        <div>
          <pre className={cx(ui.mono, ui.pre)} style={{ fontSize: 12, margin: 0, padding: '6px 8px', background: 'var(--bg-subtle)', borderRadius: 6 }}>{c.commandLine}</pre>
          {c.status === 'needs_confirmation' && <Button size="sm" variant="primary" style={{ marginTop: 6 }} onClick={() => setConfirm(true)}>确认命令行</Button>}
        </div>
      )}
      {(c.protocol === 'mcp_http' || c.protocol === 'http') && <div className={cx(ui.mono, ui.faint)} style={{ fontSize: 12 }}>{c.config.url ?? c.config.base_url}</div>}
      {c.secrets.length > 0 && (
        <div className={cx(ui.row, ui.wrap)} style={{ gap: 8, alignItems: 'flex-end' }}>
          {c.secrets.map((s) => (
            <Field key={s.name} label={<>密钥 <code>{s.name}</code> {s.configured ? <Badge tone="ok">已配置{s.hint ? ` · ${s.hint}` : ''}</Badge> : <Badge tone="warn">未配置</Badge>}</>}>
              <input className={ui.input} type="password" autoComplete="new-password" placeholder={s.configured ? '留空表示不变' : '输入值'} value={secrets[s.name] ?? ''} onChange={(e) => setSecrets({ ...secrets, [s.name]: e.target.value })} />
            </Field>
          ))}
          <Button size="sm" loading={busy === 'secrets'} disabled={!Object.values(secrets).some(Boolean)}
            onClick={() => void act('secrets', async () => { await api.patch(`/connectors/${c.id}`, { secrets: Object.fromEntries(Object.entries(secrets).filter(([, v]) => v)) }); setSecrets({}); }, '已保存密钥，需要重新测试')}>保存密钥</Button>
        </div>
      )}
      {c.lastTest && (
        <div className={ui.faint} style={{ fontSize: 12 }}>
          最近测试 {fmt.ago(c.lastTest.at)}：{c.lastTest.ok ? `成功 · ${c.lastTest.server?.name ?? ''} ${c.lastTest.server?.version ?? ''} · ${mcp ? 'MCP ' : ''}${c.lastTest.server?.protocolVersion ?? ''} · ${c.lastTest.toolCount} 个工具` : `失败 · ${c.lastTest.error ?? ''}`}
        </div>
      )}
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 16, fontSize: 13 }}>
        {(
          <label className={ui.row} style={{ gap: 6 }}>
            <input type="checkbox" aria-label={`权威数据源 ${c.name}`} checked={c.authoritative} disabled={busy === 'trust'}
              onChange={(e) => { if (e.target.checked) setTrust(true); else void act('trust', () => api.patch(`/connectors/${c.id}`, { authoritative: false })); }} />权威数据源
            <span className={ui.faint} style={{ fontSize: 12 }}>（结果可直接作为判断依据；其他连接器的结果只作为待确认的前提）</span>
          </label>
        )}
      </div>
      {c.tools.length > 0 && (
        <div className={ui.faint} style={{ fontSize: 12.5 }}>
          Agent（审计、对话、推送）可以按工具说明直接调用开放的工具（{c.tools.filter((t) => t.exposed).length}/{c.tools.length}），读写都默认开放，不需要的可以关闭；参数中含疑似注入指令，或会话读到过被审代码中的疑似注入指令时，这次调用会先暂停，在工作台“待我处理”中由你批准后执行。
        </div>
      )}
      {c.tools.length > 0 && (
        <div className={ui.card} style={{ overflow: 'auto' }}>
          <table className={ui.table}>
            <thead><tr><th>工具</th>{!mcp && <th>操作类型</th>}<th>向 Agent 开放</th></tr></thead>
            <tbody>{c.tools.map((t) => (
              <tr key={t.name}>
                <td><span className={ui.mono}>{t.name}</span>{t.description && <div className={ui.faint} style={{ fontSize: 12, maxWidth: 520, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={t.description}>{t.description}</div>}</td>
                {!mcp && <td>{t.readOnlyHint === true ? <Badge tone="ok">读取</Badge> : <Badge tone="warn">写入</Badge>}</td>}
                <td><input type="checkbox" aria-label={`向 Agent 开放 ${t.name}`} checked={exposure[t.name] ?? t.exposed}
                  onChange={(e) => {
                    const exposed = e.target.checked;
                    setExposure({ ...exposure, [t.name]: exposed });
                    void act('tools', () => api.patch(`/connectors/${c.id}`, { tools: [{ name: t.name, exposed }] })).then(() => setExposure((x) => { const { [t.name]: _drop, ...rest } = x; return rest; }));
                  }} /></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      )}
      <Dialog open={confirm} onClose={() => setConfirm(false)} wide title="确认命令行" footer={<>
        <Button onClick={() => setConfirm(false)}>取消</Button>
        <Button variant="primary" loading={busy === 'confirm'} onClick={() => void act('confirm', async () => { await api.post(`/connectors/${c.id}/confirm-command`, { commandHash: c.commandHash }); setConfirm(false); }, '已确认')}>确认运行此命令</Button>
      </>}>
        <p className={ui.muted} style={{ margin: 0 }}>下面的命令会在本机运行（不经过 shell，不继承本服务的环境变量，工作目录为专用空目录）。请确认它来自可信来源；之后命令、参数、环境变量或脚本内容有任何变化都需要重新确认。</p>
        <pre className={cx(ui.mono, ui.pre, ui.card)} style={{ padding: 10, fontSize: 12.5 }}>{c.commandLine}</pre>
        {c.protocol === 'http' && c.config.pack && confirm && <PackScripts name={c.config.pack} />}
      </Dialog>
      <ConfirmDialog open={trust} onClose={() => setTrust(false)} level="normal" title={`把 ${c.name} 设为权威数据源`} confirmText="设为权威数据源"
        onConfirm={() => void act('trust', () => api.patch(`/connectors/${c.id}`, { authoritative: true }), '已设为权威数据源').then(() => setTrust(false))}>
        只把记录系统事实的数据源设为权威（配置中心、CMDB、网关配置接口等），不要用于多人可编辑的 Wiki、工单或文档。设为权威后，Agent 可以直接依据它的查询结果确认、维持或排除漏洞，
        结论会记录调用与返回内容作为证据；某次结果出错或含疑似注入内容时，该次结果仍按未核实处理。
      </ConfirmDialog>
      <ConfirmDialog open={del} onClose={() => setDel(false)} level="destructive" title={`删除连接器 ${c.name}`} confirmText="删除"
        onConfirm={() => void act('delete', () => api.del(`/connectors/${c.id}`), '已删除').then(() => setDel(false))}>连接器的配置与密钥会一起删除。</ConfirmDialog>
    </div>
  );
}

/** Script contents shown before confirming (the user confirms what will run). */
function PackScripts({ name }: { name: string }) {
  const q = useQuery({ queryKey: ['connector-pack', name], queryFn: () => api.get<{ files: { path: string; text: string }[] }>(`/connector-packs/${name}`) });
  return <>{(q.data?.files ?? []).filter((f) => f.path.startsWith('scripts/')).map((f) => (
    <div key={f.path}><div className={ui.faint} style={{ fontSize: 12 }}>{f.path}</div><pre aria-label={`脚本 ${f.path}`} className={cx(ui.mono, ui.pre, ui.card)} style={{ padding: 10, fontSize: 12, maxHeight: 260, overflow: 'auto', margin: 0 }}>{f.text}</pre></div>
  ))}</>;
}

/**
 * 连接器包: connectors that call a pack directly — its command-line commands or HTTP API, no MCP —
 * then the packs themselves (installed, examples, AI drafts from OpenAPI).
 */
function PacksSection({ connectors, loading, onEdit, onAdd }: { connectors: ConnectorDto[]; loading: boolean; onEdit: (c: ConnectorDto) => void; onAdd: (pack: string | null) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const packs = useQuery({ queryKey: ['connector-packs'], queryFn: () => api.get<ConnectorPackDto[]>('/connector-packs') });
  const examples = useQuery({ queryKey: ['connector-packs', 'examples'], queryFn: () => api.get<ConnectorPackDto[]>('/connector-packs/examples') });
  const drafts = useQuery({ queryKey: ['connector-pack-drafts'], queryFn: () => api.get<ConnectorPackDraftDto[]>('/connector-pack-drafts'), refetchInterval: (q) => (q.state.data?.some((d) => d.status === 'organizing') ? 1500 : false) });
  const [gen, setGen] = useState(false);
  const [review, setReview] = useState<string | null>(null);
  const refresh = () => Promise.all([qc.invalidateQueries({ queryKey: ['connector-packs'] }), qc.invalidateQueries({ queryKey: ['connector-pack-drafts'] })]);
  const installed = new Set((packs.data ?? []).map((p) => p.name));
  return (
    <Section title="连接器包" actions={<div className={ui.row} style={{ gap: 6 }}><Button size="sm" onClick={() => setGen(true)}>从 OpenAPI 生成</Button><Button variant="primary" size="sm" icon="plus" disabled={!(packs.data ?? []).some((p) => p.valid)} onClick={() => onAdd(null)}>添加</Button></div>}>
      <p className={ui.faint} style={{ fontSize: 13, marginTop: 0 }}>不经过 MCP，按包中声明的命令直接调用：本机命令行工具（如飞书 lark-cli，使用它自己的登录）或 HTTP 接口（如 Jira REST API）。包是一个目录（<code>CONNECTOR.md</code> + <code>operations.yaml</code>，可带认证 / 调用脚本），放在数据目录的 <code>connectors/</code> 下；命令与脚本在你确认后由受控执行器运行，HTTP 调用经过出站检查。</p>
      {loading ? <Loading /> : connectors.length > 0 && <div className={ui.stack} style={{ marginBottom: 16 }}>{connectors.map((c) => <ConnectorCard key={c.id} c={c} onEdit={() => onEdit(c)} />)}</div>}
      <div className={ui.faint} style={{ fontSize: 12, margin: '4px 0 6px' }}>包</div>
      <div className={ui.stack}>
        {(packs.data ?? []).map((p) => (
          <div key={p.name} className={ui.card} style={{ padding: 10 }}>
            <div className={ui.spread}>
              <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}><b>{p.name}</b>{p.valid ? <Badge tone="ok">有效</Badge> : <Badge tone="danger" title={p.errors.join('\n')}>无效</Badge>}{p.scripts.length > 0 && <Badge tone="warn">含脚本（{p.interpreter}）</Badge>}</div>
              {p.valid && <Button size="sm" onClick={() => onAdd(p.name)}>用此包添加连接器</Button>}
            </div>
            <div className={ui.faint} style={{ fontSize: 12 }}>{p.valid ? `${p.description} · 读 ${p.operations.filter((o) => o.kind === 'read').length} / 写 ${p.operations.filter((o) => o.kind === 'write').length} 个操作${p.secrets.length ? ` · 密钥 ${p.secrets.join('、')}` : ''}` : p.errors.join('；')}</div>
          </div>
        ))}
        {(examples.data ?? []).filter((e) => !installed.has(e.name)).map((e) => (
          <div key={e.name} className={ui.card} style={{ padding: 10 }}>
            <div className={ui.spread}><span><b>{e.name}</b> <Badge>示例</Badge></span><Button size="sm" onClick={() => void api.post(`/connector-packs/examples/${e.name}/install`).then(() => { toast.ok('已安装'); return refresh(); }, (x) => toast.error(x))}>安装示例</Button></div>
            <div className={ui.faint} style={{ fontSize: 12 }}>{e.description}</div>
          </div>
        ))}
        {(drafts.data ?? []).map((d) => (
          <div key={d.id} className={ui.card} style={{ padding: 10 }}>
            <div className={ui.spread}><span><b>{d.name ?? '（生成中）'}</b> <Badge tone={d.status === 'ready' ? 'warn' : d.status === 'failed' ? 'danger' : 'info'}>{d.status === 'ready' ? '待审核' : d.status === 'failed' ? '失败' : 'AI 生成中'}</Badge></span>
              {d.status !== 'organizing' && <Button size="sm" onClick={() => setReview(d.id)}>审核</Button>}</div>
            {d.error && <div className={ui.error}>{d.error}</div>}
          </div>
        ))}
      </div>
      <GeneratePackDialog open={gen} onClose={() => setGen(false)} onCreated={() => void refresh()} />
      <PackDraftDialog id={review} onClose={() => { setReview(null); void refresh(); }} />
    </Section>
  );
}

function GeneratePackDialog({ open, onClose, onCreated }: { open: boolean; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [openapi, setOpenapi] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) { setOpenapi(''); setName(''); } }, [open]);
  return (
    <Dialog open={open} onClose={onClose} wide title="从 OpenAPI 生成连接器包" footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!openapi.trim()} onClick={() => { setBusy(true); void api.post('/connector-pack-drafts', { openapi, ...(name.trim() ? { name: name.trim() } : {}) }).then(() => { toast.ok('AI 正在生成，完成后在列表中审核'); onCreated(); onClose(); }, (e) => toast.error(e)).finally(() => setBusy(false)); }}>交给 AI 生成</Button>
    </>}>
      <p className={ui.muted} style={{ margin: 0 }}>粘贴对方系统的 OpenAPI 文档（JSON 或 YAML）。AI 只生成声明式操作（不写脚本），并标出读写；生成的是草稿，审核后才成为连接器包。签名、token 交换等复杂认证需要人工补充认证脚本。</p>
      <Field label="包名（可选）" hint="小写字母、数字、连字符"><input className={ui.input} value={name} onChange={(e) => setName(e.target.value)} /></Field>
      <textarea aria-label="OpenAPI 文档" className={cx(ui.textarea, ui.mono)} style={{ minHeight: '40vh', fontSize: 12 }} value={openapi} onChange={(e) => setOpenapi(e.target.value)} />
    </Dialog>
  );
}

function PackDraftDialog({ id, onClose }: { id: string | null; onClose: () => void }) {
  const toast = useToast();
  const q = useQuery({ queryKey: ['connector-pack-draft', id], enabled: !!id, queryFn: () => api.get<Omit<ConnectorPackDraftDto, 'files'> & { files: { path: string; text: string }[] }>(`/connector-pack-drafts/${id}`) });
  const d = q.data;
  return (
    <Dialog open={!!id} onClose={onClose} wide="xl" title={`连接器包草稿 · ${d?.name ?? ''}`} footer={d && d.status === 'ready' ? <>
      <Button variant="danger" onClick={() => void api.post(`/connector-pack-drafts/${id}/reject`).then(onClose, (e) => toast.error(e))}>驳回</Button>
      <Button variant="primary" disabled={d.errors.length > 0} onClick={() => void api.post(`/connector-pack-drafts/${id}/approve`).then(() => { toast.ok('已成为连接器包'); onClose(); }, (e) => toast.error(e))}>审核通过</Button>
    </> : undefined}>
      {d?.errors.length ? <div className={ui.banner} role="alert">格式问题：{d.errors.join('；')}</div> : null}
      {(d?.files ?? []).map((f) => (
        <div key={f.path}><div className={ui.faint} style={{ fontSize: 12 }}>{f.path}</div><pre className={cx(ui.mono, ui.pre, ui.card)} style={{ padding: 10, fontSize: 12, maxHeight: '40vh', overflow: 'auto', margin: 0 }}>{f.text}</pre></div>
      ))}
    </Dialog>
  );
}

export function ConnectorsSection() {
  const q = useConnectors();
  const [edit, setEdit] = useState<{ kind: 'mcp' | 'pack'; existing: ConnectorDto | null; pack?: string | null } | null>(null);
  const [importing, setImporting] = useState(false);
  const mcp = (q.data ?? []).filter((c) => c.protocol !== 'http');
  const direct = (q.data ?? []).filter((c) => c.protocol === 'http');
  return (
    <>
      <p className={ui.muted}>连接器的结果作为外部数据交给 Agent，只能作为推测使用。连接器的工具（读和写）默认向 Agent 开放，可以在工具列表中逐个关闭。Agent 的写调用直接执行并记录；调用中带有来自被审代码的疑似指令时，转为待你批准。</p>
      <Section title="MCP 连接器" actions={<div className={ui.row} style={{ gap: 6 }}><Button size="sm" onClick={() => setImporting(true)}>从已有配置导入</Button><Button variant="primary" size="sm" icon="plus" onClick={() => setEdit({ kind: 'mcp', existing: null })}>添加</Button></div>}>
        <p className={ui.faint} style={{ fontSize: 13, marginTop: 0 }}>通过 MCP 服务（本机命令 stdio 或 streamable HTTP）接入外部系统；可以从 Cursor、Claude Code 等工具已有的 MCP 配置导入。</p>
        {q.isLoading ? <Loading /> : !mcp.length ? (
          <div className={ui.card}><EmptyState icon="link" title="还没有 MCP 连接器" action={<Button variant="primary" icon="plus" onClick={() => setEdit({ kind: 'mcp', existing: null })}>添加 MCP 连接器</Button>}>接入工单、文档或配置系统后，Agent 可以在审计中查询代码以外的上下文。</EmptyState></div>
        ) : <div className={ui.stack}>{mcp.map((c) => <ConnectorCard key={c.id} c={c} onEdit={() => setEdit({ kind: 'mcp', existing: c })} />)}</div>}
      </Section>
      <PacksSection connectors={direct} loading={q.isLoading} onEdit={(c) => setEdit({ kind: 'pack', existing: c })} onAdd={(pack) => setEdit({ kind: 'pack', existing: null, pack })} />
      <ImportMcpDialog open={importing} onClose={() => setImporting(false)} />
      <ConnectorDialog open={edit !== null} kind={edit?.kind ?? 'mcp'} existing={edit?.existing ?? null} presetPack={edit?.pack ?? null} onClose={() => setEdit(null)} />
    </>
  );
}
