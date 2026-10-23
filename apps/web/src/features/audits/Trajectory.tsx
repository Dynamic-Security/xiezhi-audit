// Behaviour trajectory: structured timeline grouped by step (parallel hunts fold into
// their own groups), type filters + search in the URL, expandable details, links to vulnerabilities.
import { useEffect, useMemo, useState } from 'react';
import type { AuditDetailDto, EventDto, ExecCandidateDto, StepDto } from '@xiezhi/contracts';
import { useExecution, useFindings, useSteps, useTrajectory } from '../../shared/api/queries';
import {
  AUDIT_STATUS, BUDGET_STAGE, EVENT_LABEL, INTERVENTION, PARTIAL_REASON, SESSION_STATUS, STATUS_REASON, STEP_KIND, STEP_STATUS, TRAJECTORY_FILTERS, cacheHitText, categoryLabel, fmt, toolArgs, toolLabel,
} from '../../shared/format/messages';
import { Badge, EmptyState, Icon, Loading, cx, ui, type IconName } from '../../shared/ui';
import A from './audits.module.css';
import { CANDIDATE_STATUS, CandidateRow, headline } from './candidates';
import { SEGMENT_LABEL, StatusBar } from './StatusBar';
import { FALLBACK_REASON, ModelBadge, RunningPanel } from './Running';
import { addSubEvent, subGoal, subNoSlot, type SubNode } from './subagent';

const ICON: Record<string, IconName> = {
  'file.read': 'file', 'tool.called': 'tool', 'knowledge.loaded': 'book', 'connector.queried': 'link', 'connector.write_requested': 'link', 'connector.write_decided': 'link', 'question.asked': 'help', 'question.answered': 'user',
  'intervention.received': 'user', 'intervention.applied': 'check', 'finding.submitted': 'target', 'finding.challenged': 'shield', 'finding.reconciled': 'layers',
  'vuln.created': 'bug', 'vuln.matched': 'bug', 'vuln.impact_changed': 'bug', 'step.status_changed': 'activity', 'audit.status_changed': 'activity',
  'session.started': 'sparkle', 'session.ended': 'sparkle', 'error': 'alert', 'contract.violation': 'alert', 'security.blocked': 'shield',
  injection_suspected: 'alert', 'gate.evaluated': 'checkCircle', 'budget.exhausted': 'clock', 'budget.topped_up': 'clock', 'plan.generated': 'sparkle',
  'plan.confirmed': 'check', 'state.updated': 'bulb', 'coverage.updated': 'target', 'agent.note': 'sparkle',
  'task.started': 'layers', 'task.finished': 'layers', 'session.queued': 'clock', 'session.dequeued': 'clock',
  'candidate.marked': 'target', 'candidate.settled': 'target', 'model.fallback': 'alert',
};

/** A candidate id without its repository prefix, for one-line summaries. */
/** A candidate id in one line: `repo:path#L14:21:cmdi` → `AdminController.java:14（命令注入）`; entries keep their route. */
const shortCandidate = (id: string) => {
  const sink = /^[^:]+:(.+)#L(\d+):\d+:([\w-]+)$/.exec(id);
  if (sink) return `${sink[1]!.split('/').pop()}:${sink[2]}（${categoryLabel(sink[3]!)}）`;
  return id.replace(/^[^:]+:/, '');
};

const s = (v: unknown) => (v === undefined || v === null ? '' : String(v));
const label = (map: Record<string, string>, v: unknown) => map[s(v)] ?? s(v);

export function summarize(e: EventDto, result?: EventDto): { text: string; tone?: 'danger' | 'warn' | 'ok' | 'accent'; vuln?: string } {
  const p = e.payload;
  switch (e.type) {
    case 'file.read': return { text: `读取 ${s(p.repo)}:${s(p.path)}:${s(p.startLine)}-${s(p.endLine)}` };
    case 'tool.called': {
      const r = result?.payload;
      const total = (r?.summary as { total?: number } | undefined)?.total;
      const res = r ? (r.ok ? (total !== undefined ? ` → ${total} 条结果` : '') : ' → 失败') : ' …';
      const args = toolArgs(s(p.tool), p.args);
      return { text: `${toolLabel(s(p.tool))}${args ? ` ${args}` : ''}${res}`, ...(r && !r.ok ? { tone: 'warn' as const } : {}) };
    }
    case 'tool.result': return { text: `${toolLabel(s(p.tool))} ${p.ok ? '完成' : '失败'}` };
    case 'knowledge.loaded': return { text: p.skill ? `加载知识 ${s(p.skill)}${p.reason ? `：${s(p.reason)}` : ''}` : `知识索引 ${s(p.items)} 条${(p.bodies as string[] | undefined)?.length ? `，正文：${(p.bodies as string[]).join('、')}` : ''}` };
    case 'connector.write_requested': return { text: `调用 ${s(p.connector)} · ${s(p.operation)} 已暂停，等你在工作台批准（${p.held_because === 'session' ? '会话读到过被审代码中的疑似注入指令' : '参数含疑似注入内容'}）${p.reason ? ` — ${s(p.reason)}` : ''}`, tone: 'warn' };
    case 'connector.write_decided': return p.decision === 'rejected'
      ? { text: `已拒绝调用 ${s(p.connector)} · ${s(p.operation)}${p.note ? `：${s(p.note)}` : ''}` }
      : { text: `已批准并执行 ${s(p.connector)} · ${s(p.operation)}：${p.status === 'ok' ? '成功' : `失败${p.error ? `（${s(p.error)}）` : ''}`}`, tone: p.status === 'ok' ? 'ok' : 'danger' };
    // A repeated identical write answered from the stored call; a write past the per-step limit.
    case 'connector.queried': if (p.replayed_from) return { text: `连接器 ${s(p.connector)} · ${s(p.operation)}：与之前成功的一次写调用相同，没有再次执行，返回上次的结果` };
      if (p.status === 'refused') return { text: `连接器 ${s(p.connector)} · ${s(p.operation)}：这一步的写调用已达上限，没有执行`, tone: 'warn' };
      return { text: `查询连接器 ${s(p.connector)} · ${s(p.operation)}：${p.status === 'ok' ? `${s(p.bytes)} 字节（外部数据，未核实）` : `失败（${s(p.status)}）`}${p.reason ? ` — ${s(p.reason)}` : ''}`, ...(p.status !== 'ok' ? { tone: 'warn' as const } : {}) };
    case 'question.asked': return { text: `Agent 提问：${s(p.text)}${p.blocking ? '（影响结论）' : ''}`, tone: 'accent' };
    case 'question.answered': return { text: p.dismissed ? '提问已忽略' : `用户回答：${s(p.text)}` };
    // Pause requests are recorded as interventions by the engine (kind `pause`, fixed English text).
    case 'intervention.received': return { text: p.kind === 'pause' ? '用户请求暂停：进行中的会话做完这一轮后停下' : `用户介入（${INTERVENTION[s(p.kind)] ?? s(p.kind)}）：${s(p.text)}`, tone: 'accent' };
    case 'intervention.applied': return { text: `介入已生效：${(p.applied as string[] | undefined)?.join('、') ?? ''}` };
    case 'finding.submitted': return { text: `提交发现${p.count !== undefined ? ` ${s(p.count)} 条` : ''}${p.titles ? ` ${s(p.titles)}` : ''}` };
    case 'finding.challenged': return { text: `对抗复核：${p.confirmation === 'pending' ? '转为待确认' : p.confirmation === 'refuted' ? '反驳，转为待确认' : '维持'}（置信度 ${s(p.confidence_delta ?? p.delta ?? '')}）` };
    case 'finding.reconciled': return { text: `归并：提交 ${s(p.sent)}，正式 ${s(p.canonical)}，证据不足 ${s(p.insufficient)}，合并 ${s(p.merged)}，丢弃 ${s(p.dropped)}` };
    case 'vuln.created': return { text: `新漏洞 V-${s(p.display_no)}（${p.confirm_status === 'confirmed' ? '已确认' : '待确认'}）`, tone: 'danger', vuln: s(p.vulnerability_id) };
    case 'vuln.matched': return { text: `匹配已有漏洞 V-${s(p.display_no)}`, vuln: s(p.vulnerability_id) };
    case 'vuln.impact_changed': return { text: `漏洞影响面变化：新增入口 ${(p.added_entries as string[] | undefined)?.join('、') ?? ''}`, vuln: s(p.vulnerability_id) };
    case 'step.status_changed': return { text: `${STEP_KIND[s(p.kind)] ?? s(p.kind)}：${STEP_STATUS[s(p.to)] ?? s(p.to)}${p.error_class ? `（${s(p.error_class)}）` : ''}`, ...(p.to === 'failed' ? { tone: 'danger' as const } : p.to === 'succeeded' ? { tone: 'ok' as const } : {}) };
    case 'audit.status_changed': return { text: `审计状态：${p.from ? label(AUDIT_STATUS, p.from) : '—'} → ${label(AUDIT_STATUS, p.to)}${p.reason ? `（${label(STATUS_REASON, p.reason)}）` : ''}` };
    case 'session.started': return { text: `会话开始 · ${s((p.model as { model?: string } | undefined)?.model ?? p.model)}` };
    case 'session.ended': return { text: `会话结束：${label(SESSION_STATUS, p.status)}，${s(p.turns)} 回合`, ...(p.status !== 'completed' ? { tone: 'warn' as const } : {}) };
    case 'error': return { text: `错误 ${s(p.error_class)}：${s(p.summary)}${p.retrying ? '（将重试）' : ''}`, tone: 'danger' };
    case 'model.fallback': {
      const to = p.to as { provider?: string; model?: string } | undefined;
      const why = FALLBACK_REASON[s(p.reason)] ?? s(p.reason);
      return p.degraded
        ? { text: `${s(p.from)} ${why}；备用模型也在交叉审查组里，不替换，这一路记为交叉审查降级`, tone: 'warn' }
        : { text: `${s(p.from)} ${why}，切换到备用模型 ${s(to?.provider)}/${s(to?.model)} 重试`, tone: 'warn' };
    }
    case 'contract.violation': return { text: `输出不合规（${s(p.tool)}）：${(p.issues as string[] | undefined)?.slice(0, 2).join('；') ?? ''}`, tone: 'warn' };
    case 'security.blocked': return { text: `安全拦截 ${s(p.tool)}：${s(p.reason)}`, tone: 'warn' };
    case 'injection_suspected': return { text: `疑似指令内容 ${s(p.repo)}:${s(p.path)}（${s(p.signal)}），已作为数据处理`, tone: 'warn' };
    case 'gate.evaluated': return { text: `完成闸门：${label(AUDIT_STATUS, p.status)}${(p.partial_reasons as string[] | undefined)?.length ? ` · ${(p.partial_reasons as string[]).map((r) => label(PARTIAL_REASON, r)).join('、')}` : ''}`, tone: p.status === 'completed' ? 'ok' : 'warn' };
    case 'budget.exhausted': return { text: `预算不足，建议追加 ${fmt.n(Number(p.suggested_top_up_tokens ?? 0))} tokens`, tone: 'warn' };
    case 'budget.topped_up': return { text: `已追加预算` };
    case 'plan.generated': return { text: '审计计划已生成' };
    case 'plan.confirmed': return { text: '计划已确认，策略已冻结' };
    case 'state.updated': return { text: `更新认知状态` };
    // sub-agents and waits for a session slot or the global model gate.
    case 'task.started': return { text: `派出子 Agent：${s(p.goal)}`, tone: 'accent' };
    case 'candidate.marked': return { text: `候选 ${shortCandidate(s(p.candidate))}：${label(CANDIDATE_STATUS, p.status)}（初步）${p.note ? ` — ${s(p.note)}` : ''}`, ...(p.status === 'finding' ? { tone: 'danger' as const } : {}) };
    case 'candidate.settled': return { text: `候选 ${shortCandidate(s(p.candidate))} 结论：${label(CANDIDATE_STATUS, p.status)}${p.changedFrom ? `（初步为「${label(CANDIDATE_STATUS, p.changedFrom)}」，以提交为准）` : ''}`, ...(p.changedFrom ? { tone: 'warn' as const } : {}) };
    case 'task.finished': return { text: `子 Agent ${p.status === 'completed' ? '完成' : `结束（${label(SESSION_STATUS, p.status)}）`}${p.turns !== undefined ? ` · ${s(p.turns)} 回合` : ''}${took(p.ms) ? ` · ${took(p.ms)}` : ''}`, ...(p.status !== 'completed' ? { tone: 'warn' as const } : {}) };
    // Risk-hypothesis-first: the threat model's list, then one verdict per hypothesis with its reason.
    case 'judgement.made':
      if (p.kind === 'threat_model') return { text: `威胁建模：${s(p.repo)} 列出 ${s(p.hypotheses)} 条风险假设，接下来逐条验证`, tone: 'accent' };
      if (p.kind === 'hypothesis_verified') {
        const v = p.status === 'confirmed' ? '已证实' : p.status === 'refuted' ? '已排除' : '无法判定';
        return { text: `风险假设「${s(p.statement)}」${v}：${s(p.reason)}`, ...(p.status === 'confirmed' ? { tone: 'danger' as const } : p.status === 'open' ? { tone: 'warn' as const } : {}) };
      }
      // The service breaker and its probes.
      if (p.kind === 'service_breaker') return { text: `模型服务连续 ${s(p.failures)} 次无响应：审计暂停，系统定时探测，恢复后自动继续`, tone: 'warn' };
      if (p.kind === 'service_probe') return p.gave_up
        ? { text: '探测模型服务已满一天仍无响应，停止探测；可以手动继续', tone: 'warn' }
        : { text: p.ok ? `第 ${s(p.attempt)} 次探测：模型服务已恢复，审计自动继续` : `第 ${s(p.attempt)} 次探测：模型服务仍无响应（${s(p.detail)}）`, ...(p.ok ? {} : { tone: 'warn' as const }) };
      return { text: EVENT_LABEL[e.type] ?? e.type };
    case 'session.paused': return p.reason === 'cost'
      ? { text: '已达到成本上限：会话在这一轮之后停下，审计以已有结果收尾', tone: 'warn' as const }
      : p.reason === 'budget'
      ? { text: `${BUDGET_STAGE[p.stage as string] ?? s(p.stage)}的额度已用完：会话在这一轮之后暂停，追加预算后从这里继续`, tone: 'warn' as const }
      : { text: '会话在这一轮之后暂停，继续后从这里接着做', tone: 'warn' as const };
    case 'session.resumed': return { text: `从暂停处继续（第 ${s(p.fromAttempt)} 次尝试的会话，${s(p.messages)} 条消息）${p.repaired ? `；补上了 ${s(p.repaired)} 个中断的工具调用结果` : ''}` };
    case 'session.queued': return { text: p.wait === 'slot' ? '等待会话名额（本次审计的并发已满）' : '等待模型（全局并发已满）' };
    case 'session.dequeued': return { text: p.gaveUp ? `没有等到会话名额（${took(p.ms)}），由父 Agent 自行调查` : `${p.wait === 'slot' ? '拿到会话名额' : '开始请求模型'}，等待 ${took(p.ms)}`, ...(p.gaveUp ? { tone: 'warn' as const } : {}) };
    default: return { text: EVENT_LABEL[e.type] ?? e.type };
  }
}

/** Lifecycle bookkeeping, hidden unless “显示系统事件” (the narrative is what the Agent did and said). */
function isSystem(e: EventDto): boolean {
  if (e.type === 'session.started' || e.type === 'session.ended' || e.type === 'plan.confirmed' || e.type === 'plan.generated') return true;
  if (e.type === 'session.queued' || (e.type === 'session.dequeued' && !e.payload.gaveUp)) return true;
  if ((e.type === 'candidate.marked' && e.payload.status === 'investigating') || (e.type === 'candidate.settled' && !e.payload.changedFrom)) return true;
  if (e.type === 'step.status_changed') return ['ready', 'running', 'pending', 'succeeded'].includes(s(e.payload.to));
  if (e.type === 'audit.status_changed') return ['planning', 'queued', 'running', 'awaiting_confirm'].includes(s(e.payload.to));
  return false;
}
const took = (ms: unknown) => { const n = Number(ms); return Number.isFinite(n) && n > 0 ? (n < 1000 ? `${n} ms` : `${(n / 1000).toFixed(1)} s`) : ''; };
const pretty = (v: unknown) => { try { return JSON.stringify(v, null, 2); } catch { return String(v); } };
const repoOf = (e: EventDto) => s(e.payload.repo ?? (e.payload.args as { repo?: string } | undefined)?.repo);

/** What the Agent said in a turn (model output, shown as data). */
function NoteRow({ e }: { e: EventDto }) {
  const [open, setOpen] = useState(false);
  const text = s(e.payload.text);
  const long = text.length > 240 || text.split('\n').length > 3;
  const tokens = Number(e.payload.input ?? 0) + Number(e.payload.output ?? 0);
  return (
    <li className={A.note}>
      <span className={A.tlTime}>{fmt.time(e.ts)}</span>
      <div className={A.noteBody}>
        <span className={A.noteWho}>Agent</span>
        <span className={cx(A.noteText, !open && long && A.noteClamp)}>{text}</span>
        <span className={A.noteMeta}>
          {long && <button className={A.noteMore} onClick={() => setOpen(!open)}>{open ? '收起' : '展开'}</button>}
          {e.payload.truncated ? '（已截断）' : ''}{tokens > 0 ? `${fmt.compact(tokens)} tokens` : ''}
        </span>
      </div>
    </li>
  );
}

function Item({ e, result, onVuln }: { e: EventDto; result?: EventDto | undefined; onVuln: (vid: string) => void }) {
  const [open, setOpen] = useState(false);
  const [raw, setRaw] = useState(false);
  const sum = summarize(e, result);
  const duration = e.type === 'tool.called' ? took(result?.payload.duration_ms) : '';
  return (
    <li className={A.tlItem}>
      <button className={cx(A.tlRow, sum.tone && A[`tone_${sum.tone}`])} onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className={A.tlTime}>{fmt.time(e.ts)}</span>
        <span className={A.tlIcon}><Icon name={ICON[e.type] ?? 'activity'} size={14} /></span>
        <span className={A.tlText}>{sum.text}</span>
        {duration && <span className={A.tlDur}>{duration}</span>}
        {sum.vuln && <span className={A.tlLink} onClick={(ev) => { ev.stopPropagation(); onVuln(sum.vuln!); }}>查看 ↗</span>}
      </button>
      {open && (
        <div className={A.tlDetail}>
          {e.type === 'tool.called' && e.payload.args !== undefined && <><div className={A.tlDetailHead}>参数</div><pre className={ui.pre}>{pretty(e.payload.args)}</pre></>}
          {'preview' in e.payload && typeof e.payload.preview === 'string' && <><div className={A.tlDetailHead}>内容</div><pre className={ui.pre}>{e.payload.preview}</pre></>}
          {result && typeof result.payload.preview === 'string' && <><div className={A.tlDetailHead}>结果{duration ? ` · ${duration}` : ''}</div><pre className={ui.pre}>{result.payload.preview}</pre></>}
          <button className={A.noteMore} onClick={() => setRaw(!raw)}>{raw ? '隐藏原始数据' : '查看原始数据'}</button>
          {raw && <pre className={ui.pre}>{pretty({ ...e.payload, ...(e.payload.preview ? { preview: '…' } : {}) })}</pre>}
          <div className={ui.faint}>#{e.seq} · {e.type}</div>
        </div>
      )}
    </li>
  );
}

/** Live numbers of the run: output speed, cache hits, calls, turns — from the loaded trajectory. */
function Stats({ audit, items }: { audit: AuditDetailDto; items: EventDto[] }) {
  const notes = items.filter((e) => e.type === 'agent.note');
  const input = notes.reduce((n, e) => n + Number(e.payload.input ?? 0), 0);
  const cached = notes.reduce((n, e) => n + Number(e.payload.cache_read ?? 0), 0);
  const output = notes.reduce((n, e) => n + Number(e.payload.output ?? 0), 0);
  const seconds = audit.budget.consumed.durationMs / 1000;
  const calls = items.filter((e) => e.type === 'tool.called').length;
  const cells: [string, string][] = [
    // Below a few seconds of runtime the rate is noise (e.g. replayed or cached runs).
    ['输出速度', seconds >= 5 && output > 0 ? `${(output / seconds).toFixed(1)} tok/s` : '—'],
    ['缓存命中', cacheHitText(input, cached)],
    ['工具调用', String(calls)],
    ['模型轮数', String(notes.length)],
  ];
  return (
    <div className={A.stats} aria-label="运行统计">
      {cells.map(([k, v]) => <div key={k}><span className={ui.faint}>{k}</span><b>{v}</b></div>)}
    </div>
  );
}

/** The candidates of a step inside its trajectory group, collapsed by default. */
function CandidateList({ cands }: { cands: ExecCandidateDto[] }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={A.candBox}>
      <button className={A.subHead} aria-expanded={open} onClick={() => setOpen(!open)}>
        <Icon name={open ? 'chevronDown' : 'chevronRight'} size={13} />候选清单（{cands.length}）
      </button>
      {open && <ul className={A.candList}>{cands.map((c) => <CandidateRow key={c.id} c={c} />)}</ul>}
    </div>
  );
}

type Node = { kind: 'event'; e: EventDto } | SubNode;
interface Group { key: string; step: StepDto | null; events: EventDto[]; nodes: Node[] }
const sessionOf = (e: EventDto) => e.payload.session as { id: string; role: 'main' | 'task'; parent?: string } | undefined;

function SubAgentNode({ n, results, onVuln }: { n: SubNode; results: Map<string, EventDto>; onVuln: (vid: string) => void }) {
  const f = n.finished?.payload;
  const running = !n.finished;
  const noSlot = subNoSlot(n);
  const goal = subGoal(n);
  const [open, setOpen] = useState<boolean | null>(null);
  const expanded = open ?? running;
  const turns = n.events.filter((e) => e.type === 'agent.note').length;
  return (
    <li className={A.subNode}>
      <button className={A.subHead} aria-expanded={expanded} onClick={() => setOpen(!expanded)}>
        <Icon name={expanded ? 'chevronDown' : 'chevronRight'} size={13} />
        <Icon name="layers" size={13} />
        <span className={A.subGoal}>子 Agent：{goal || '（目标未记录）'}</span>
        {running ? <Badge tone="accent" dot pulse>进行中</Badge>
          : noSlot ? <Badge tone="warn">未开始</Badge>
          : <Badge tone={f?.status === 'completed' ? 'ok' : 'warn'}>{f?.status === 'completed' ? '完成' : label(SESSION_STATUS, f?.status)}</Badge>}
        <span className={ui.faint} style={{ marginLeft: 'auto', fontSize: 12 }}>
          {[f?.turns !== undefined ? `${s(f.turns)} 回合` : turns ? `${turns} 回合` : '', took(f?.ms), n.events.filter((e) => e.type === 'tool.called').length ? `${n.events.filter((e) => e.type === 'tool.called').length} 次调用` : ''].filter(Boolean).join(' · ')}
        </span>
      </button>
      {expanded && (
        <ul className={A.tlList}>
          {n.events.map((e) => e.type === 'agent.note'
            ? <NoteRow key={e.seq} e={e} />
            : <Item key={e.seq} e={e} result={e.type === 'tool.called' ? results.get(`${e.stepId}:${s(e.payload.call_id)}`) : undefined} onVuln={onVuln} />)}
        </ul>
      )}
    </li>
  );
}

export function TrajectoryView({ aid, audit, types, q, step, onTypes, onQ, onVuln, onStep }: {
  aid: string; audit?: AuditDetailDto; types: string[]; q: string; step?: string | undefined; onTypes: (t: string[]) => void; onQ: (q: string) => void;
  onVuln: (vid: string) => void; onStep?: (stepId: string | undefined) => void;
}) {
  const traj = useTrajectory(aid, types, q);
  const execution = useExecution(aid, !!audit && !['completed', 'partial', 'failed', 'cancelled'].includes(audit.status));
  const execSteps = useMemo(() => new Map((execution.data?.phases ?? []).flatMap((p) => p.steps).map((x) => [x.id, x])), [execution.data]);
  const steps = useSteps(aid);
  const findings = useFindings(aid);
  const [text, setText] = useState(q);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [system, setSystem] = useState(false);
  const [repo, setRepo] = useState<string | null>(null);
  /** A job segment picked in the status bar: only its steps are shown. */
  const [segment, setSegment] = useState<string | null>(null);
  useEffect(() => { const t = setTimeout(() => { if (text !== q) onQ(text); }, 300); return () => clearTimeout(t); }, [text]);

  const { groups, results } = useMemo(() => {
    const items = traj.data?.items ?? [];
    const results = new Map<string, EventDto>();
    for (const e of items) if (e.type === 'tool.result') results.set(`${e.stepId}:${s(e.payload.call_id)}`, e);
    // A `read` call is followed by its file.read record: show the call once.
    const readCalls = new Set(items.filter((e) => e.type === 'tool.called' && e.payload.tool === 'read').map((e) => `${e.stepId}|${s((e.payload.args as { path?: string } | undefined)?.path)}`));
    const byStep = new Map((steps.data ?? []).map((st) => [st.id, st]));
    const groups: Group[] = [];
    let cur: Group | null = null;
    for (const e of items) {
      if (e.type === 'tool.result' && results.get(`${e.stepId}:${s(e.payload.call_id)}`) === e && items.some((x) => x.type === 'tool.called' && x.stepId === e.stepId && s(x.payload.call_id) === s(e.payload.call_id))) continue;
      if (e.type === 'file.read' && readCalls.has(`${e.stepId}|${s(e.payload.path)}`)) continue;
      // A progress mark is shown by its readable `candidate.marked` line, not as a raw tool call.
      if ((e.type === 'tool.called' || e.type === 'tool.result') && e.payload.tool === 'mark_candidate') continue;
      if (e.type === 'agent.note' && !s(e.payload.text).trim()) continue;
      if (!system && !types.length && isSystem(e)) continue;
      if (repo && repoOf(e) && repoOf(e) !== repo) continue;
      const key = e.stepId ?? 'audit';
      if (!cur || cur.key !== key) {
        // Re-open an existing group for interleaved parallel steps to keep each branch together.
        const existing = groups.find((g) => g.key === key && key !== 'audit');
        if (existing) { cur = existing; } else { cur = { key, step: e.stepId ? byStep.get(e.stepId) ?? null : null, events: [], nodes: [] }; groups.push(cur); }
      }
      cur.events.push(e);
      // Sub-agent events go under the sub-agent's node; its start and end make the node's header.
      const sess = sessionOf(e);
      if (sess?.role === 'task') {
        let n = cur.nodes.find((x): x is SubNode => x.kind === 'sub' && x.id === sess.id);
        if (!n) { n = { kind: 'sub', id: sess.id, started: null, finished: null, events: [] }; cur.nodes.push(n); }
        addSubEvent(n, e);
      } else cur.nodes.push({ kind: 'event', e });
    }
    return { groups, results };
  }, [traj.data, steps.data, system, types.length, repo]);

  const shown = segment ? groups.filter((g) => g.step && execSteps.get(g.step.id)?.segment === segment) : groups;
  const repos = audit?.repos ?? [];
  const linked = (findings.data ?? []).filter((f) => f.state === 'canonical');
  return (
    <div>
      {audit && execution.data && (
        <StatusBar x={execution.data} audit={audit} selected={segment} onSelect={(k) => { setSegment(k); document.querySelector('[aria-label="作业进度"]')?.scrollIntoView({ block: 'start' }); }} />
      )}
      {execution.data && (
        <RunningPanel x={execution.data} onFocus={(id) => {
          setSegment(null);
          setCollapsed((c) => ({ ...c, [id]: false }));
          onStep?.(id);
          requestAnimationFrame(() => document.getElementById(`step-${id}`)?.scrollIntoView({ block: 'start', behavior: 'smooth' }));
        }} />
      )}
      {audit && !types.length && !q && <Stats audit={audit} items={traj.data?.items ?? []} />}
      <div className={A.tlFilters}>
        <div className={A.search}><Icon name="search" size={14} /><input placeholder="搜索轨迹" value={text} onChange={(e) => setText(e.target.value)} /></div>
        {TRAJECTORY_FILTERS.map((f) => {
          const on = types.includes(f.key);
          return <button key={f.key} className={cx(ui.chip, on && ui.chipOn)} aria-pressed={on} onClick={() => onTypes(on ? types.filter((t) => t !== f.key) : [...types, f.key])}>{f.label}</button>;
        })}
      </div>
      <div className={A.tlFilters}>
        <label className={ui.checkbox} style={{ fontSize: 12 }}><input type="checkbox" checked={system} onChange={(e) => setSystem(e.target.checked)} />显示系统事件</label>
        {repos.length > 1 && (
          <select className={ui.select} style={{ width: 180, height: 28, fontSize: 12 }} aria-label="按仓库筛选" value={repo ?? ''} onChange={(e) => setRepo(e.target.value || null)}>
            <option value="">全部仓库</option>
            {repos.map((r) => <option key={r.id} value={r.name}>{r.name}</option>)}
          </select>
        )}
        {onStep && linked.length > 0 && (
          <select className={ui.select} style={{ width: 240, height: 28, fontSize: 12 }} aria-label="按发现定位" value={linked.find((f) => f.stepId === step)?.id ?? ''}
            onChange={(e) => onStep(linked.find((f) => f.id === e.target.value)?.stepId)}>
            <option value="">定位到某条发现的来源…</option>
            {linked.map((f) => <option key={f.id} value={f.id}>{f.displayNo ? `F-${f.displayNo} ` : ''}{f.title}</option>)}
          </select>
        )}
      </div>
      {traj.isLoading ? <Loading rows={8} /> : shown.length === 0 ? <EmptyState icon="activity" title="暂无轨迹">{segment ? `「${SEGMENT_LABEL[segment] ?? segment}」还没有轨迹。` : '审计开始后，Agent 的每一步都会实时出现在这里。'}</EmptyState> : (
        <div className={A.groups}>
          {shown.map((g) => {
            const isCollapsed = collapsed[g.key] ?? (step && !segment ? g.key !== step : false);
            const st = g.step;
            const secs = st?.startedAt ? ((st.endedAt ? new Date(st.endedAt).getTime() : Date.now()) - new Date(st.startedAt).getTime()) : 0;
            const calls = g.events.filter((e) => e.type === 'tool.called').length;
            const ex = g.step ? execSteps.get(g.step.id) : undefined;
            return (
              <section key={g.key} id={`step-${g.key}`} className={cx(A.group, step === g.key && A.groupHi)}>
                <button className={A.groupHead} onClick={() => setCollapsed({ ...collapsed, [g.key]: !isCollapsed })} aria-expanded={!isCollapsed}>
                  <Icon name={isCollapsed ? 'chevronRight' : 'chevronDown'} size={14} />
                  {/* The cross-repository system model is a profile step with lineage SYSTEM. */}
                  <b>{st ? (st.kind === 'profile' && st.lineage === 'SYSTEM' ? '系统理解（跨仓库）' : STEP_KIND[st.kind] ?? st.kind) : '审计'}</b>
                  {st?.lineage && st.lineage !== 'SYSTEM' && <span className={ui.mono} style={{ fontSize: 11, color: 'var(--text-3)' }}>{st.lineage}</span>}
                  {ex && ex.candidates.length > 0 && <span className={A.groupHeadline}>{ex.subject ? `${ex.subject} · ` : ''}{headline(ex.candidates)} · 已有结论 {ex.candidates.filter((c) => !['pending', 'investigating'].includes(c.status)).length}/{ex.candidates.length}</span>}
                  {ex && !ex.candidates.length && (ex.subject || ex.repo) && <span className={A.groupHeadline}>{ex.subject ?? ex.repo}</span>}
                  {ex?.fallback && <ModelBadge s={ex} />}
                  {st && <Badge tone={st.status === 'succeeded' ? 'ok' : st.status === 'failed' ? 'danger' : st.status === 'running' ? 'accent' : 'neutral'} dot pulse={st.status === 'running'}>{STEP_STATUS[st.status]}</Badge>}
                  <span className={ui.faint} style={{ marginLeft: 'auto', fontSize: 12 }}>
                    {[secs > 0 ? fmt.duration(secs) : '', calls ? `${calls} 次调用` : `${g.events.length} 项`, st && st.tokensIn + st.tokensOut > 0 ? `${fmt.compact(st.tokensIn + st.tokensOut)} tokens` : ''].filter(Boolean).join(' · ')}
                  </span>
                </button>
                {!isCollapsed && ex && ex.candidates.length > 0 && <CandidateList key={`${g.key}-c`} cands={ex.candidates} />}
                {!isCollapsed && (
                  <ul className={A.tlList}>
                    {g.nodes.map((n) => n.kind === 'sub'
                      ? <SubAgentNode key={n.id} n={n} results={results} onVuln={onVuln} />
                      : n.e.type === 'agent.note'
                        ? <NoteRow key={n.e.seq} e={n.e} />
                        : <Item key={n.e.seq} e={n.e} result={n.e.type === 'tool.called' ? results.get(`${n.e.stepId}:${s(n.e.payload.call_id)}`) : undefined} onVuln={onVuln} />)}
                  </ul>
                )}
              </section>
            );
          })}
          {traj.data?.hasMore && <p className={ui.faint}>只显示前 2000 条，使用筛选缩小范围。</p>}
        </div>
      )}
    </div>
  );
}
