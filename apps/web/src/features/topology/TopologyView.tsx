// System topology: repositories and services as a layered graph (frontend →
// gateway → services → shared libraries / contracts → external services). Every connection shows its
// source (AI / imported / user) and confidence (confirmed solid, inferred dashed); selecting one shows
// the code evidence. Users may add or remove connections and project-external services.
import { useMemo, useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { TopologyDto, TopologyEdgeDto, TopologyNodeDto } from '@xiezhi/contracts';
import { api, ApiError } from '../../shared/api/client';
import { ROLE } from '../../shared/format/messages';
import { Badge, Button, EmptyState, ErrorState, Field, Loading, cx, ui, useToast } from '../../shared/ui';
import { ArchitectureImportDialog } from './ArchitectureImportDialog';
import type { GatewayExposureDto } from '@xiezhi/contracts';

export const EDGE_KIND: Record<string, string> = { contract: '接口契约', client_call: '客户端调用', message: '消息', shared_lib: '共享库', frontend_api: '前端 API 调用' };
export const PROTOCOL: Record<string, string> = { http: 'HTTP', grpc: 'gRPC', dubbo: 'Dubbo', mq: 'MQ', gateway_route: '网关路由', shared_lib: '依赖' };
const ORIGIN: Record<string, string> = { ai: 'AI 从代码识别', imported: '架构资料导入', user: '用户添加' };
const KIND_COLOR: Record<string, string> = { frontend_api: 'var(--info)', client_call: 'var(--accent)', message: 'var(--warn)', shared_lib: 'var(--text-3)', contract: 'var(--ok)' };

const NODE_W = 168;
const NODE_H = 44;
const COL_GAP = 96;
const ROW_GAP = 22;

function layer(n: TopologyNodeDto): number {
  if (n.kind === 'external_service') return 4;
  if (n.role === 'frontend') return 0;
  if (n.kind === 'gateway' || n.role === 'gateway') return 1;
  if (n.role === 'shared_lib' || n.role === 'api_def') return 3;
  return 2;
}

export const useTopology = (pid: string) => useQuery({ queryKey: ['project', pid, 'topology'], queryFn: () => api.get<TopologyDto>(`/projects/${pid}/topology`) });

function Graph({ t, selected, onSelect }: { t: TopologyDto; selected: string | null; onSelect: (id: string) => void }) {
  const { pos, width, height } = useMemo(() => {
    const cols = new Map<number, TopologyNodeDto[]>();
    for (const n of t.nodes) cols.set(layer(n), [...(cols.get(layer(n)) ?? []), n]);
    const used = [...cols.keys()].sort((a, b) => a - b);
    const pos = new Map<string, { x: number; y: number }>();
    let maxRows = 0;
    used.forEach((c, ci) => {
      const list = cols.get(c)!.sort((a, b) => a.name.localeCompare(b.name));
      maxRows = Math.max(maxRows, list.length);
      list.forEach((n, i) => pos.set(n.id, { x: 16 + ci * (NODE_W + COL_GAP), y: 16 + i * (NODE_H + ROW_GAP) }));
    });
    // Vertically centre shorter columns.
    const h = 32 + maxRows * (NODE_H + ROW_GAP) - ROW_GAP;
    for (const c of used) {
      const list = cols.get(c)!;
      const off = (maxRows - list.length) * (NODE_H + ROW_GAP) / 2;
      for (const n of list) pos.get(n.id)!.y += off;
    }
    return { pos, width: 32 + used.length * (NODE_W + COL_GAP) - COL_GAP, height: h };
  }, [t]);
  const edges = t.edges.filter((e) => !e.removed);
  return (
    <div style={{ overflowX: 'auto' }}>
      <svg role="img" aria-label="系统拓扑图" width={width} height={height} style={{ display: 'block', minWidth: width }}>
        <defs>
          {Object.entries(KIND_COLOR).map(([k, c]) => (
            <marker key={k} id={`arrow-${k}`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M0 0 L10 5 L0 10 z" fill={c} />
            </marker>
          ))}
        </defs>
        {edges.map((e, i) => {
          const a = pos.get(e.from);
          const b = pos.get(e.to);
          if (!a || !b) return null;
          // Forward: right side → left side. Same column: loop out on the right. Backward: under the nodes.
          const same = b.x === a.x;
          const forward = b.x > a.x;
          let d: string;
          if (forward) {
            const [x1, y1, x2, y2] = [a.x + NODE_W, a.y + NODE_H / 2, b.x, b.y + NODE_H / 2];
            const bend = (x2 - x1) / 2;
            d = `M${x1},${y1} C${x1 + bend},${y1} ${x2 - bend},${y2} ${x2},${y2}`;
          } else if (same) {
            const [x, y1, y2] = [a.x + NODE_W, a.y + NODE_H / 2 + 6, b.y + NODE_H / 2 - 6];
            const out = 36 + (i % 3) * 14;
            d = `M${x},${y1} C${x + out},${y1} ${x + out},${y2} ${x},${y2}`;
          } else {
            const [x1, y1, x2, y2] = [a.x + NODE_W / 2, a.y + NODE_H, b.x + NODE_W / 2, b.y + NODE_H];
            const bend = 40 + (i % 3) * 12;
            d = `M${x1},${y1} C${x1},${y1 + bend} ${x2},${y2 + bend} ${x2},${y2}`;
          }
          const on = selected === e.id;
          return (
            <g key={e.id} style={{ cursor: 'pointer' }} onClick={() => onSelect(e.id)}>
              <path d={d} fill="none" stroke="transparent" strokeWidth={12} />
              <path d={d} fill="none" stroke={KIND_COLOR[e.kind]} strokeWidth={on ? 3 : 1.6} strokeDasharray={e.confidence === 'inferred' ? '6 4' : undefined} markerEnd={`url(#arrow-${e.kind})`} opacity={selected && !on ? 0.35 : 1}>
                <title>{`${EDGE_KIND[e.kind]} · ${PROTOCOL[e.protocol]} · ${e.confidence === 'confirmed' ? '已确认' : '推断'} · ${ORIGIN[e.origin]}`}</title>
              </path>
            </g>
          );
        })}
        {t.nodes.map((n) => {
          const p = pos.get(n.id)!;
          const ext = n.kind === 'external_service';
          return (
            <g key={n.id} transform={`translate(${p.x},${p.y})`}>
              <rect width={NODE_W} height={NODE_H} rx={10} fill={ext ? 'var(--bg-muted)' : 'var(--bg-elevated)'} stroke={ext ? 'var(--border-strong)' : 'var(--border)'} strokeDasharray={ext ? '4 3' : undefined} />
              <text x={12} y={18} fontSize={13} fontWeight={600} fill="var(--text)">{n.name.length > 20 ? `${n.name.slice(0, 19)}…` : n.name}</text>
              <text x={12} y={34} fontSize={11} fill="var(--text-3)">{ext ? '项目外服务' : n.kind === 'gateway' ? '网关' : ROLE[n.role ?? 'unknown'] ?? '仓库'}</text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function Evidence({ e, name }: { e: TopologyEdgeDto; name: (id: string) => string }) {
  return (
    <div className={ui.card} style={{ padding: 12 }}>
      <div className={cx(ui.row, ui.wrap)}>
        <b>{name(e.from)} → {name(e.to)}</b>
        <Badge>{EDGE_KIND[e.kind]}</Badge><Badge>{PROTOCOL[e.protocol]}</Badge>
        <Badge tone={e.confidence === 'confirmed' ? 'ok' : 'warn'}>{e.confidence === 'confirmed' ? '已确认' : '推断'}</Badge>
        <Badge>{ORIGIN[e.origin]}</Badge>
      </div>
      {e.evidence.length === 0 ? <p className={ui.faint} style={{ fontSize: 13 }}>用户添加的连接，没有代码证据。</p> : (
        <div className={ui.stack} style={{ marginTop: 8 }}>
          {e.evidence.map((ev, i) => !ev.consumer ? (
            <div key={i} className={ui.faint} style={{ fontSize: 12 }}>· {ev.source?.startsWith('doc:') ? `架构资料「${ev.source.slice(4)}」` : ev.source ?? '导入'}：{ev.reason}（推断，未经代码核实）</div>
          ) : (
            <div key={i} className={cx(ui.mono, ui.faint)} style={{ fontSize: 12 }}>
              · {ev.consumer.repo}:{ev.consumer.path || '(构建文件)'}{ev.consumer.line ? `:${ev.consumer.line}` : ''} {String(ev.consumer.key.method ?? '')} {String(ev.consumer.key.pathTemplate ?? ev.consumer.key.topic ?? ev.consumer.key.service ?? ev.consumer.key.interface ?? ev.consumer.key.module ?? '')}
              {ev.provider && <> → {ev.provider.repo}:{ev.provider.path || '(构建文件)'}{ev.provider.line ? `:${ev.provider.line}` : ''} {String(ev.provider.key.pathTemplate ?? ev.provider.key.topic ?? ev.provider.key.service ?? '')}</>}
              <span> （{ev.reason}；{ev.confidence === 'confirmed' ? '已确认' : '推断'}）</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function TopologyView({ pid }: { pid: string }) {
  const topo = useTopology(pid);
  const [sel, setSel] = useState<string | null>(null);
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [extName, setExtName] = useState('');
  const [kind, setKind] = useState('client_call');
  const [protocol, setProtocol] = useState('http');
  const [busy, setBusy] = useState(false);
  const [importing, setImporting] = useState(false);
  const qc = useQueryClient();
  const toast = useToast();
  const navigate = useNavigate();
  if (topo.isLoading) return <Loading />;
  if (topo.error) return <ErrorState error={topo.error} />;
  const t = topo.data!;
  const name = (id: string) => t.nodes.find((n) => n.id === id)?.name ?? '?';
  const patch = async (body: Record<string, unknown>, ok: string) => {
    setBusy(true);
    try {
      const next = await api.patch<TopologyDto>(`/projects/${pid}/topology`, { revision: t.revision, ...body });
      qc.setQueryData(['project', pid, 'topology'], next);
      toast.ok(ok);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'COMMON_REVISION_CONFLICT') await qc.invalidateQueries({ queryKey: ['project', pid, 'topology'] });
      toast.error(e);
    }
    setBusy(false);
  };
  if (t.nodes.length === 0) {
    return <>
      <div className={ui.card}><EmptyState icon="layers" title="还没有拓扑" action={<div className={ui.row}><Button variant="primary" onClick={() => void navigate({ to: '/projects/$pid', params: { pid }, search: { tab: 'repos' } })}>去仓库页分析</Button><Button onClick={() => setImporting(true)}>导入架构资料</Button></div>}>在“仓库”页点“分析仓库”后，会根据代码识别仓库之间的调用关系；也可以导入架构文档或服务清单。</EmptyState></div>
      <ArchitectureImportDialog pid={pid} open={importing} onClose={() => setImporting(false)} />
    </>;
  }
  const selected = t.edges.find((e) => e.id === sel) ?? null;
  const externals = t.nodes.filter((n) => n.kind === 'external_service');
  const addEdge = () => {
    const target = to === '__new' ? `new:${extName.trim()}` : to;
    void patch({
      ...(to === '__new' ? { addNodes: [{ name: extName.trim(), kind: 'external_service' }] } : {}),
      addEdges: [{ from, to: target, kind, protocol }],
    }, '已添加连接');
    setExtName('');
  };
  return (
    <div className={ui.stack}>
      <div className={ui.card} style={{ padding: 12 }}>
        <div className={cx(ui.row, ui.wrap)} style={{ marginBottom: 8, fontSize: 12 }}>
          {Object.entries(EDGE_KIND).map(([k, l]) => <span key={k} className={ui.faint}><span style={{ display: 'inline-block', width: 18, height: 3, background: KIND_COLOR[k], verticalAlign: 'middle', marginRight: 4 }} />{l}</span>)}
          <span className={ui.faint}>实线 = 已确认，虚线 = 推断；虚线框 = 项目外服务</span>
        </div>
        <Graph t={t} selected={sel} onSelect={(id) => setSel(id === sel ? null : id)} />
        <div className={ui.row} style={{ justifyContent: 'flex-end', marginTop: 8 }}><Button size="sm" onClick={() => setImporting(true)}>导入架构资料</Button></div>
      </div>
      <ArchitectureImportDialog pid={pid} open={importing} onClose={() => setImporting(false)} />
      {externals.length > 0 && (
        <div className={ui.card} style={{ padding: 12 }}>
          <b>项目外服务</b>
          <p className={ui.muted} style={{ fontSize: 13 }}>这些服务被项目内的代码调用，但项目里没有它们的代码：{externals.map((n) => n.name).join('、')}。添加对应仓库后重新分析，跨仓的“待确认”结论才能继续核实。</p>
          <Button size="sm" icon="plus" onClick={() => void navigate({ to: '/projects/$pid', params: { pid }, search: { tab: 'repos', addRepo: 1 } })}>添加仓库</Button>
        </div>
      )}
      {selected && <Evidence e={selected} name={name} />}
      <div className={ui.card} style={{ overflow: 'auto' }}>
        <table className={ui.table}>
          <thead><tr><th>连接</th><th>类型</th><th>来源</th><th>可信程度</th><th>证据</th><th /></tr></thead>
          <tbody>
            {t.edges.map((e) => (
              <tr key={e.id} style={{ opacity: e.removed ? 0.5 : 1, background: sel === e.id ? 'var(--bg-active)' : undefined }}>
                <td><button style={{ background: 'none', border: 0, padding: 0, font: 'inherit', color: 'var(--text)', cursor: 'pointer' }} onClick={() => setSel(e.id)}>{name(e.from)} → {name(e.to)}</button>{e.removed && <Badge>已删除</Badge>}</td>
                <td>{EDGE_KIND[e.kind]} · {PROTOCOL[e.protocol]}</td>
                <td>{ORIGIN[e.origin]}</td>
                <td>{e.confidence === 'confirmed' ? <Badge tone="ok">已确认</Badge> : <Badge tone="warn">推断</Badge>}</td>
                <td>{e.evidence.length}</td>
                <td>{e.removed
                  ? <Button size="sm" disabled={busy} onClick={() => void patch({ restoreEdges: [e.id] }, '已恢复')}>恢复</Button>
                  : <Button size="sm" variant="ghost" disabled={busy} aria-label={`删除连接 ${name(e.from)} → ${name(e.to)}`} onClick={() => void patch({ removeEdges: [e.id] }, '已删除')}>删除</Button>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className={ui.card} style={{ padding: 12 }}>
        <b>补充连接</b>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 8, marginTop: 8, alignItems: 'end' }}>
          <Field label="调用方"><select aria-label="调用方" className={ui.input} value={from} onChange={(e) => setFrom(e.target.value)}><option value="">选择…</option>{t.nodes.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}</select></Field>
          <Field label="被调用方"><select aria-label="被调用方" className={ui.input} value={to} onChange={(e) => setTo(e.target.value)}><option value="">选择…</option>{t.nodes.map((n) => <option key={n.id} value={n.id}>{n.name}</option>)}<option value="__new">新的项目外服务…</option></select></Field>
          {to === '__new' && <Field label="服务名"><input aria-label="项目外服务名" className={ui.input} value={extName} onChange={(e) => setExtName(e.target.value)} placeholder="例如 payment-gateway" /></Field>}
          <Field label="类型"><select aria-label="连接类型" className={ui.input} value={kind} onChange={(e) => setKind(e.target.value)}>{Object.entries(EDGE_KIND).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
          <Field label="协议"><select aria-label="协议" className={ui.input} value={protocol} onChange={(e) => setProtocol(e.target.value)}>{Object.entries(PROTOCOL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
          <Button variant="primary" disabled={busy || !from || !to || from === to || (to === '__new' && !extName.trim())} onClick={addEdge}>添加</Button>
        </div>
      </div>
      <GatewayExposure pid={pid} />
    </div>
  );
}

const AUTH_KIND: Record<string, string> = { jwt: 'JWT', oauth2: 'OAuth2 / OIDC', key: 'API Key', basic: 'Basic', external: '外部鉴权', custom: '自定义鉴权', off: '已关闭' };

/** the entry-exposure map — the gateways' routes and whether each authenticates before forwarding. */
function GatewayExposure({ pid }: { pid: string }) {
  const q = useQuery({ queryKey: ['gateway-exposure', pid], queryFn: () => api.get<GatewayExposureDto>(`/projects/${pid}/gateway-exposure`) });
  const gws = q.data?.gateways ?? [];
  if (!gws.length) return null;
  return (
    <section style={{ marginTop: 20 }} aria-label="入口暴露">
      <h2 style={{ fontSize: 15, marginBottom: 4 }}>入口暴露（网关）</h2>
      <p className={ui.faint} style={{ fontSize: 12, margin: '0 0 8px' }}>由网关配置确定性提取：每条路由转发到哪个服务、转发前是否鉴权、设置或移除了哪些请求头。审计据此判断服务入口是否已由网关统一认证（不代表服务内可以省略归属等校验），并存为项目的企业事实。</p>
      {gws.map((g) => (
        <div key={g.gateway} className={ui.card} style={{ overflow: 'auto', marginBottom: 10 }}>
          <div style={{ padding: '8px 12px' }}><b>{g.gateway}</b>{g.global.length ? <span className={ui.faint} style={{ fontSize: 12 }}> · 全局鉴权：{g.global.map((a) => `${AUTH_KIND[a.kind] ?? a.kind}（${a.mechanism}）`).join('；')}</span> : <span className={ui.faint} style={{ fontSize: 12 }}> · 没有全局鉴权</span>}</div>
          <table className={ui.table} aria-label={`${g.gateway} 的路由`}>
            <thead><tr><th>路由</th><th>转发到</th><th>鉴权</th><th>请求头</th></tr></thead>
            <tbody>{g.routes.map((r) => (
              <tr key={`${r.pathTemplate}-${r.line}`}>
                <td className={ui.mono}>{r.pathTemplate}{r.stripPrefix ? <span className={ui.faint}>（去掉前 {r.stripPrefix} 段）</span> : null}</td>
                <td>{r.upstream ?? '—'}</td>
                <td>{r.effectiveAuth ? <Badge tone="ok">{AUTH_KIND[r.effectiveAuth.kind] ?? r.effectiveAuth.kind}{r.auth ? '' : '（全局）'}</Badge> : <Badge tone="warn">{r.auth?.kind === 'off' ? '已关闭鉴权' : '不经鉴权'}</Badge>}</td>
                <td className={ui.faint} style={{ fontSize: 12 }}>{[...r.setHeaders.map((h) => `设置 ${h}`), ...r.removeHeaders.map((h) => `移除 ${h}`)].join('、') || '—'}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ))}
    </section>
  );
}
