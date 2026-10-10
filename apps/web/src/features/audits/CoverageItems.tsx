// Coverage items: entries read as external interfaces (source) — protocol, method and route, handler, auth;
// sinks read as risky functions (sink) — the call, category, tainted argument, enclosing function and line. Grouped,
// filtered, uncovered first; a row opens the snapshot source at the line and the full conclusion.
import { Fragment, useMemo, useState } from 'react';
import type { CoverageItemDetail, CoverageItemDto } from '@xiezhi/contracts';
import { useSource } from '../../shared/api/queries';
import { categoryLabel } from '../../shared/format/messages';
import { Badge, CodeView, Icon, Segmented, Spinner, cx, ui } from '../../shared/ui';
import A from './audits.module.css';

type EntryDetail = Extract<CoverageItemDetail, { type: 'entry' }>;
type SinkDetail = Extract<CoverageItemDetail, { type: 'sink' }>;

export const PROTOCOL: Record<string, string> = {
  http: 'HTTP', grpc: 'gRPC', graphql: 'GraphQL', signalr: 'SignalR', websocket: 'WebSocket', socketio: 'Socket.IO', stomp: 'STOMP', broadcast: '广播频道',
  kafka: 'Kafka', rabbitmq: 'RabbitMQ', jms: 'JMS', redis: 'Redis', rocketmq: 'RocketMQ', nats: 'NATS', nsq: 'NSQ', celery: 'Celery', dramatiq: 'Dramatiq',
  bullmq: 'BullMQ', masstransit: 'MassTransit', nservicebus: 'NServiceBus', 'azure-servicebus': 'Service Bus', 'laravel-queue': 'Laravel 队列',
  'symfony-messenger': 'Symfony Messenger', 'nest-microservice': 'Nest 微服务', cron: '定时任务', 'hosted-service': '后台服务', cli: '命令行', thrift: 'Thrift', dubbo: 'Dubbo',
};
const KIND: Record<string, string> = { http: 'HTTP', rpc: 'RPC', socket: '长连接', message: '消息消费', schedule: '定时任务', cli: '命令行', internal: '内部' };
/** Entries reachable from outside: these should show an auth signal. Timed jobs and commands are not. */
const EXPOSED = new Set(['http', 'rpc', 'socket', 'message']);

const STATUS: Record<string, { l: string; t: 'ok' | 'warn' | 'danger' | 'neutral' | 'info' }> = {
  concluded: { l: '已结论', t: 'ok' }, read: { l: '已读未结论', t: 'warn' }, uncovered: { l: '未覆盖', t: 'danger' }, excluded: { l: '范围外', t: 'neutral' }, failed: { l: '缺口', t: 'danger' },
};
const VERDICT: Record<string, { l: string; t: 'ok' | 'warn' | 'danger' | 'neutral' }> = {
  finding: { l: '有发现', t: 'danger' }, suspicious: { l: '可疑', t: 'warn' }, ruled_out: { l: '已排除', t: 'ok' }, no_issue: { l: '无问题', t: 'ok' },
};
const isGap = (s: string) => s !== 'concluded' && s !== 'excluded';

/** `ruled_out: reason` → { tag, reason }. */
function verdictOf(v: string | null): { tag: string | null; reason: string | null } {
  if (!v) return { tag: null, reason: null };
  const m = /^([a-z_]+)(?::\s*([\s\S]*))?$/.exec(v.trim());
  return m && VERDICT[m[1]!] ? { tag: m[1]!, reason: m[2]?.trim() || null } : { tag: null, reason: v };
}
const fileOf = (p: string) => p.split('/').pop() ?? p;
const dirOf = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/') + 1) : '');
/** The line a row points at: the handler / call line from the detail, else the start of the read range. */
const lineOf = (i: CoverageItemDto) => (i.detail && i.detail.line > 0 ? i.detail.line : i.startLine);

function entryOf(i: CoverageItemDto): EntryDetail {
  return i.detail?.type === 'entry' ? i.detail : { type: 'entry', entryKind: 'http', protocol: 'http', framework: '', method: null, route: i.targetId.replace(/^[^:]*:/, ''), handler: null, line: 0, middlewares: [], auth: [] };
}
function sinkOf(i: CoverageItemDto): SinkDetail {
  return i.detail?.type === 'sink' ? i.detail : { type: 'sink', api: '', line: i.startLine, column: null, taintHint: null, function: null };
}
/** A native PHP script served as a page: no method, route is the file (`/login.php`). */
const isPage = (d: EntryDetail) => !d.method && d.protocol === 'http' && /\.php$/i.test(d.route ?? '');

function Conclusion({ i }: { i: CoverageItemDto }) {
  const v = verdictOf(i.verdict);
  const st = STATUS[i.status] ?? { l: i.status, t: 'neutral' as const };
  const tag = i.status === 'concluded' && v.tag ? VERDICT[v.tag]! : null;
  return (
    <div className={A.covVerdict}>
      <Badge tone={tag?.t ?? st.t}>{tag ? `${st.l} · ${tag.l}` : st.l}</Badge>
      {v.reason && <div className={cx(ui.faint, ui.ellipsis)} title={v.reason}>{v.reason}</div>}
    </div>
  );
}

function EntryCells({ i, repoTag }: { i: CoverageItemDto; repoTag: boolean }) {
  const d = entryOf(i);
  const signals = [...d.auth, ...d.middlewares.filter((m) => !d.auth.includes(m))];
  return (
    <>
      <td className={A.covMain}>
        <div className={A.covIface}>
          {repoTag && <span className={A.covRepo}>{i.repo}</span>}
          {isPage(d) ? <span className={A.covMethod}>页面</span> : d.method ? <span className={A.covMethod}>{d.method}</span>
            : d.protocol !== 'http' ? <span className={cx(A.covMethod, A.covProto)}>{PROTOCOL[d.protocol] ?? d.protocol}</span> : null}
          <span className={cx(ui.mono, ui.ellipsis)} title={d.route ?? i.targetId}>{d.route || i.targetId}</span>
        </div>
      </td>
      <td className={A.covWhere}>
        <div className={cx(ui.mono, ui.ellipsis)} title={d.handler ?? undefined}>{d.handler ?? <span className={ui.faint}>文件顶层</span>}</div>
        <div className={cx(ui.faint, ui.mono, ui.ellipsis)} title={`${i.path}:${lineOf(i)}`}>{fileOf(i.path)}:{lineOf(i)}</div>
      </td>
      <td className={A.covAuth}>
        {signals.length ? (
          <div className={ui.ellipsis} title={signals.join('\n')}><span className={ui.mono}>{signals[0]!.slice(0, 60)}</span>{signals.length > 1 && <span className={ui.faint}> +{signals.length - 1}</span>}</div>
        ) : EXPOSED.has(d.entryKind) ? <Badge tone="warn">未发现鉴权</Badge> : <span className={ui.faint}>—</span>}
      </td>
      <td className={A.covKind}><span className={ui.faint}>{d.framework || '—'}</span></td>
    </>
  );
}

function SinkCells({ i, repoTag }: { i: CoverageItemDto; repoTag: boolean }) {
  const d = sinkOf(i);
  return (
    <>
      <td className={A.covMain}>
        <div className={A.covIface}>
          {repoTag && <span className={A.covRepo}>{i.repo}</span>}
          <span className={cx(ui.mono, ui.ellipsis)} title={d.api || i.targetId}><b>{d.api || '（未识别调用）'}</b></span>
        </div>
      </td>
      <td className={A.covKind}><Badge tone="info">{categoryLabel(i.category)}</Badge></td>
      <td className={A.covAuth}>{d.taintHint ? <span className={ui.ellipsis} title={d.taintHint}>{d.taintHint}</span> : <span className={ui.faint}>—</span>}</td>
      <td className={A.covWhere}>
        <div className={cx(ui.mono, ui.ellipsis)}>{d.function ? `${d.function}()` : <span className={ui.faint}>文件顶层</span>}</div>
        <div className={cx(ui.faint, ui.mono, ui.ellipsis)} title={`${i.path}:${lineOf(i)}`}><span>{dirOf(i.path)}</span>{fileOf(i.path)}:{lineOf(i)}</div>
      </td>
    </>
  );
}

/** Expanded row: the snapshot source around the line, the full conclusion, the internal id. */
function ItemDetail({ aid, i }: { aid: string; i: CoverageItemDto }) {
  const line = lineOf(i);
  const src = useSource(aid, i.repo, i.path, Math.max(1, line - 8), line + 12);
  const v = verdictOf(i.verdict);
  return (
    <div className={A.covDetail}>
      {v.reason && <div><b>结论：</b>{v.reason}</div>}
      {src.isLoading ? <Spinner /> : src.data ? (
        <CodeView lines={src.data.lines} from={src.data.from} highlight={[line, line]} maxHeight={260}
          title={<>审计快照 <span className={ui.mono}>{i.path}:{line}</span></>} />
      ) : null}
      <div className={ui.faint} style={{ fontSize: 12 }}>标识 <span className={ui.mono}>{i.targetId}</span>
        <button type="button" className={A.covCopy} onClick={() => void navigator.clipboard?.writeText(i.targetId).catch(() => undefined)}>复制</button></div>
    </div>
  );
}

type GroupBy = 'kind' | 'module' | 'category' | 'file';

export function CoverageItemsTable({ aid, kind, items, finished, multiRepo, onlyGaps, picked, onPick }: {
  aid: string; kind: 'entry' | 'sink'; items: CoverageItemDto[]; finished: boolean; multiRepo: boolean; onlyGaps: boolean;
  picked: Set<string>; onPick: (id: string) => void;
}) {
  const [q, setQ] = useState('');
  const [groupBy, setGroupBy] = useState<GroupBy>(kind === 'entry' ? 'kind' : 'category');
  const [noAuth, setNoAuth] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const [closed, setClosed] = useState<Set<string>>(new Set());
  const group = kind === 'entry' && groupBy !== 'kind' && groupBy !== 'module' ? 'kind' : kind === 'sink' && groupBy !== 'category' && groupBy !== 'file' ? 'category' : groupBy;

  const groups = useMemo(() => {
    const text = q.trim().toLowerCase();
    const rows = items.filter((i) => {
      if (onlyGaps && !isGap(i.status)) return false;
      if (kind === 'entry' && noAuth) { const d = entryOf(i); if (d.auth.length || d.middlewares.length || !EXPOSED.has(d.entryKind)) return false; }
      if (!text) return true;
      const d = i.detail;
      const hay = [i.targetId, i.path, d?.type === 'entry' ? `${d.route} ${d.handler ?? ''} ${d.protocol}` : d?.type === 'sink' ? `${d.api} ${d.function ?? ''}` : ''].join(' ').toLowerCase();
      return hay.includes(text);
    });
    const keyOf = (i: CoverageItemDto): [string, string] => {
      if (kind === 'entry') {
        const d = entryOf(i);
        if (group === 'kind') return [d.protocol, PROTOCOL[d.protocol] ?? d.protocol];
        const seg = (d.route ?? '').split(/[/.#:]/).filter(Boolean)[0] ?? '';
        return [seg, seg ? `/${seg}` : '（根）'];
      }
      return group === 'category' ? [i.category ?? '', categoryLabel(i.category)] : [i.path, i.path];
    };
    const map = new Map<string, { key: string; label: string; rows: CoverageItemDto[] }>();
    for (const i of rows) {
      const [k, label] = keyOf(i);
      if (!map.has(k)) map.set(k, { key: k, label, rows: [] });
      map.get(k)!.rows.push(i);
    }
    // Uncovered first; entries with no auth signal next (the exposed surface to look at first).
    const rank = (i: CoverageItemDto) => (isGap(i.status) ? 0 : 2) + (kind === 'entry' && EXPOSED.has(entryOf(i).entryKind) && !entryOf(i).auth.length && !entryOf(i).middlewares.length ? 0 : 1);
    const out = [...map.values()].map((g) => ({ ...g, rows: g.rows.sort((a, b) => rank(a) - rank(b) || a.path.localeCompare(b.path) || lineOf(a) - lineOf(b)), gaps: g.rows.filter((r) => isGap(r.status)).length }));
    return out.sort((a, b) => b.gaps - a.gaps || b.rows.length - a.rows.length || a.label.localeCompare(b.label));
  }, [items, q, onlyGaps, noAuth, kind, group]);

  const total = groups.reduce((n, g) => n + g.rows.length, 0);
  const head = kind === 'entry'
    ? <tr><th aria-label="选择" /><th>接口</th><th>处理函数</th><th>鉴权</th><th>框架</th><th>结论</th></tr>
    : <tr><th aria-label="选择" /><th>风险函数</th><th>类别</th><th>污点参数</th><th>所在位置</th><th>结论</th></tr>;
  return (
    <div className={ui.stack} style={{ gap: 8 }}>
      <div className={ui.row} style={{ flexWrap: 'wrap', gap: 8 }}>
        <input className={A.covSearch} type="search" placeholder={kind === 'entry' ? '搜索路由、主题、命令、处理函数' : '搜索函数名、文件'} value={q} onChange={(e) => setQ(e.target.value)} aria-label="搜索覆盖项" />
        <Segmented value={group} onChange={setGroupBy} items={kind === 'entry' ? [{ key: 'kind', label: '按协议' }, { key: 'module', label: '按路由前缀' }] : [{ key: 'category', label: '按类别' }, { key: 'file', label: '按文件' }]} />
        {kind === 'entry' && <label className={ui.checkbox}><input type="checkbox" checked={noAuth} onChange={(e) => setNoAuth(e.target.checked)} />只看未发现鉴权</label>}
        <span className={ui.faint} style={{ fontSize: 12 }}>{total} 项</span>
      </div>
      <div className={ui.card} style={{ overflow: 'auto', maxHeight: 560 }}>
        <table className={cx(ui.table, A.covTable)}>
          <thead>{head}</thead>
          <tbody>{groups.map((g) => {
            const shut = closed.has(g.key);
            return (
              <Fragment key={g.key}>
                <tr className={A.covGroup} onClick={() => setClosed((s) => { const n = new Set(s); if (n.has(g.key)) n.delete(g.key); else n.add(g.key); return n; })}>
                  <td colSpan={6}><Icon name={shut ? 'chevronRight' : 'chevronDown'} size={14} /> <b>{g.label}</b> <span className={ui.faint}>· {g.rows.length} 项{g.gaps ? ` · 未覆盖 ${g.gaps}` : ''}</span></td>
                </tr>
                {!shut && g.rows.map((i) => (
                  <Fragment key={i.id}>
                    <tr className={cx(A.covRow, open === i.id && A.covRowOpen)} onClick={() => setOpen((o) => (o === i.id ? null : i.id))} aria-expanded={open === i.id}>
                      <td onClick={(e) => e.stopPropagation()}>{isGap(i.status) && finished && <input type="checkbox" aria-label={`选择 ${i.targetId}`} checked={picked.has(i.id)} onChange={() => onPick(i.id)} />}</td>
                      {kind === 'entry' ? <EntryCells i={i} repoTag={multiRepo} /> : <SinkCells i={i} repoTag={multiRepo} />}
                      <td className={A.covStatus}><Conclusion i={i} /></td>
                    </tr>
                    {open === i.id && <tr><td /><td colSpan={5}><ItemDetail aid={aid} i={i} /></td></tr>}
                  </Fragment>
                ))}
              </Fragment>
            );
          })}</tbody>
        </table>
      </div>
      {kind === 'entry' && <p className={ui.faint} style={{ fontSize: 12 }}>入口类型：{Object.entries(KIND).filter(([k]) => k !== 'internal').map(([, v]) => v).join(' · ')}。“鉴权”列来自注解、中间件或过滤器的静态识别，未识别到不等于没有鉴权。</p>}
    </div>
  );
}
