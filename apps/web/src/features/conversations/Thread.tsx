// Conversation thread shared by the conversation page and the AI panel (12):
// messages with text, tool calls and cards in the order they happened; edit-and-resend of the last message;
// a draft mode where the conversation is created by the first message; the current page object as a
// removable reference above the composer.
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type ClipboardEvent, type DragEvent, type KeyboardEvent, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { ConversationDto, MentionCandidateDto, MentionDto, MessageDto, ToolCallDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { qk, useConversation, useMentionCandidates, useMessages } from '../../shared/api/queries';
import { AUDIT_STATUS, SEVERITY, fmt, toolArgsFromJson, toolLabel } from '../../shared/format/messages';
import { Markdown } from '../../shared/markdown/Markdown';
import { Badge, Button, ErrorState, Icon, Loading, cx, ui, useAutoGrow, useDismiss, useStickToBottom, useToast } from '../../shared/ui';
import { DraftDialog } from '../knowledge/drafts';
import { PendingFiles, SentFiles, attachmentsBody, readFiles, type PendingFile } from './attachments';
import { ConversationCard } from './Cards';
import { replyParts } from './parts';
import { useReplyStream } from './useReply';
import { QuickStart, nextPlaceholder } from './Templates';
import C from './conversations.module.css';

export const KIND_LABEL: Record<string, string> = { project: '项目', repo: '仓库', audit: '审计', vuln: '漏洞', skill: '知识' };
export const clientId = () => `web-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;

export function MentionChips({ mentions, onRemove, prefix }: { mentions: MentionDto[]; onRemove?: (m: MentionDto) => void; prefix?: string }) {
  if (!mentions.length) return null;
  return (
    <div className={C.chips}>
      {mentions.map((m) => (
        <span key={`${m.kind}:${m.id}`} className={cx(C.chip, !m.valid && C.chipInvalid)} title={m.valid ? m.label : '引用的对象已删除'}>
          {prefix ?? '@'}{KIND_LABEL[m.kind]} {m.valid ? m.label : '已失效'}
          {onRemove && <button className={C.chipX} aria-label={`移除引用 ${m.label}`} onClick={() => onRemove(m)}><Icon name="x" size={11} /></button>}
        </span>
      ))}
    </div>
  );
}

/** Tool results carry the data-boundary tags the model sees; the user sees the content. */
const stripBoundary = (t: string) => t.replace(/<\/?untrusted_data[^>]*>\n?/g, '');
/** Arguments arrive as one-line JSON (cut at 300 characters); expanded, they are shown indented when complete. */
const prettyArgs = (json: string) => { try { return JSON.stringify(JSON.parse(json), null, 2); } catch { return json; } };

function ToolCalls({ calls }: { calls: ToolCallDto[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className={C.tools} aria-label="工具调用">
      {calls.map((c) => (
        <div key={c.callId} className={C.tool}>
          <button className={C.toolRow} onClick={() => setOpen(open === c.callId ? null : c.callId)} aria-expanded={open === c.callId}>
            <Icon name={c.phase === 'started' ? 'clock' : c.ok === false ? 'alert' : 'tool'} size={12} />
            <span className={C.toolName}>{toolLabel(c.name)}</span>
            <span className={C.toolArgs}>{toolArgsFromJson(c.name, c.argsSummary)}</span>
            <Icon name={open === c.callId ? 'chevronDown' : 'chevronRight'} size={12} />
          </button>
          {open === c.callId && <div className={cx(C.toolDetail, c.ok === false && C.toolErr)}>{prettyArgs(c.argsSummary)}{c.resultPreview ? `\n\n${stripBoundary(c.resultPreview)}` : c.phase === 'started' ? '\n\n进行中…' : ''}</div>}
        </div>
      ))}
    </div>
  );
}

function AssistantMessage({ m, liveMid, onOpen, onEnd, onRegenerate, onSave, footerAuditId }: {
  m: MessageDto; liveMid: string | null; onOpen?: ((p: string) => void) | undefined; onEnd: () => void; onRegenerate: (m: MessageDto) => void; onSave: (m: MessageDto) => void;
  footerAuditId?: string | undefined;
}) {
  const live = liveMid === m.id && m.status === 'streaming';
  const stream = useReplyStream(live ? m.id : null, onEnd);
  const text = live ? stream.text : m.content;
  const qc = useQueryClient();
  const refresh = () => void qc.invalidateQueries({ queryKey: qk.messages(m.conversationId) });
  const parts = useMemo(() => replyParts(
    text, live ? stream.toolCalls : m.toolCalls,
    (live ? stream.cards.map((c) => ({ id: c.cardId, kind: c.kind, state: c.state, data: c.data, textOffset: c.textOffset })) : m.cards)
      .filter((c) => !(c.kind === 'audit_status' && footerAuditId && c.data.auditId === footerAuditId)),
  ), [text, live, stream.toolCalls, stream.cards, m.toolCalls, m.cards, footerAuditId]);
  const lastText = parts.map((p) => p.kind).lastIndexOf('text');
  const streamingNow = live && stream.status !== 'done';
  return (
    <div className={C.assistant}>
      <div className={C.avatar}><Icon name="sparkle" size={14} /></div>
      <div className={C.body}>
        {parts.map((p, i) => p.kind === 'text'
          ? <div key={i} className={C.text}><Markdown text={p.text} />{streamingNow && i === lastText && <span className={C.caret} aria-hidden />}</div>
          : p.kind === 'tools' ? <ToolCalls key={i} calls={p.calls} />
            : <ConversationCard key={p.card.id} card={p.card} live={live} {...(onOpen ? { onOpen } : {})} {...(live ? {} : { onChanged: refresh })} />)}
        {streamingNow && !text && stream.status !== 'error' && <div className={ui.faint} style={{ fontSize: 13 }}><span className={C.caret} aria-hidden /> 正在思考…</div>}
        {(m.status === 'interrupted' || (live && stream.status === 'error')) && (
          <div className={C.interrupted} role="status">
            <Icon name="alert" size={14} /> {m.error ?? stream.error ?? '回复中断'}
            <Button size="sm" variant="ghost" icon="refresh" onClick={() => onRegenerate(m)}>重新生成</Button>
          </div>
        )}
        {!live && m.status !== 'streaming' && (
          <div className={C.meta}>
            {m.model && <span>{m.model}</span>}
            {m.tokens > 0 && <span>{fmt.tokens(m.tokens)} tokens</span>}
            {m.finishReason === 'user_stopped' && <Badge>已停止</Badge>}
            {m.finishReason === 'max_turns' && <Badge tone="warn">达到轮数上限</Badge>}
            {m.content && <button className={C.metaBtn} onClick={() => void navigator.clipboard?.writeText(m.content)}><Icon name="copy" size={12} />复制</button>}
            {m.content && <button className={C.metaBtn} onClick={() => onSave(m)}><Icon name="book" size={12} />存为知识</button>}
            {m.status !== 'interrupted' && <button className={C.metaBtn} onClick={() => onRegenerate(m)}><Icon name="refresh" size={12} />重新生成</button>}
          </div>
        )}
      </div>
    </div>
  );
}

function UserMessage({ m, editable, onEdit }: { m: MessageDto; editable: boolean; onEdit: (m: MessageDto, text: string) => Promise<boolean> }) {
  const [editing, setEditing] = useState(false);
  const [text, setText] = useState(m.content);
  const [busy, setBusy] = useState(false);
  const ref = useAutoGrow(text, 240);
  if (editing) {
    return (
      <div className={C.user}>
        <div className={C.editBox}>
          <textarea ref={ref} className={C.input} value={text} aria-label="编辑消息" onChange={(e) => setText(e.target.value)} autoFocus />
          <div className={ui.row} style={{ justifyContent: 'flex-end' }}>
            <Button size="sm" variant="ghost" onClick={() => { setEditing(false); setText(m.content); }}>取消</Button>
            <Button size="sm" variant="primary" loading={busy} disabled={!text.trim() && !m.attachments.length} onClick={async () => { setBusy(true); if (await onEdit(m, text.trim())) setEditing(false); setBusy(false); }}>保存并重新回复</Button>
          </div>
        </div>
      </div>
    );
  }
  return (
    <div className={C.user}>
      <SentFiles messageId={m.id} files={m.attachments} />
      {m.content && <div className={C.userBubble}>{m.content}</div>}
      <MentionChips mentions={m.mentions} />
      {editable && <button className={C.metaBtn} onClick={() => setEditing(true)}><Icon name="edit" size={12} />编辑</button>}
    </div>
  );
}

/** An audit candidate's detail is its status, a vulnerability's its severity: shown in Chinese (they read “running”, “high”). */
function candidateDetail(c: MentionCandidateDto): string {
  if (c.kind === 'audit') return AUDIT_STATUS[c.detail ?? ''] ?? c.detail ?? '';
  if (c.kind === 'vuln') return SEVERITY[c.detail ?? ''] ?? c.detail ?? '';
  return c.detail ?? '';
}

/** Height of the @-mention list (conversations.module.css `.popover`). */
const POPOVER_MAX = 280;

/** Composer with @-mention autocomplete; `context` is the current page object, sent unless removed. */
export function Composer({ text, setText, disabled, streaming, onSend, onStop, context, placeholder, hint = true, autoFocus, top, fillSignal }: {
  text: string; setText: (t: string) => void; disabled?: boolean; streaming?: boolean; onSend: (text: string, mentions: MentionDto[], files: PendingFile[]) => Promise<boolean>;
  onStop?: () => void; context?: MentionDto | null; placeholder?: string | undefined; hint?: boolean; autoFocus?: boolean; top?: ReactNode;
  /** Changes when a template filled the text: focus the box and select its first 【…】. */
  fillSignal?: number;
}) {
  const [mentions, setMentions] = useState<MentionDto[]>([]);
  const [dropContext, setDropContext] = useState(false);
  const [query, setQuery] = useState<string | null>(null);
  const [active, setActive] = useState(0);
  const [busy, setBusy] = useState(false);
  const [files, setFiles] = useState<PendingFile[]>([]);
  const [adding, setAdding] = useState(false);
  const [menu, setMenu] = useState(false);
  const [dropping, setDropping] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);
  const folderInput = useRef<HTMLInputElement>(null);
  const menuRef = useDismiss(menu, useCallback(() => setMenu(false), []));
  const toast = useToast();
  const ref = useAutoGrow(text);
  const cands = useMentionCandidates(query ?? '', query !== null);
  const options = cands.data ?? [];
  // The list opens above the box; a composer near the top of the page (the workbench) opens it below instead, or its
  // first candidates — projects, repositories, audits — sit under the page header.
  const wrap = useRef<HTMLDivElement>(null);
  const [below, setBelow] = useState(false);
  const open = query !== null;
  useLayoutEffect(() => {
    if (open || menu) setBelow((wrap.current?.getBoundingClientRect().top ?? 0) < POPOVER_MAX + 80);
  }, [open, menu]);
  useEffect(() => { setDropContext(false); }, [context?.kind, context?.id]);
  const selectPlaceholder = (from: number): boolean => {
    const el = ref.current;
    const at = el ? nextPlaceholder(el.value, from) : null;
    if (!el || !at) return false;
    el.focus();
    el.setSelectionRange(at[0], at[1]);
    return true;
  };
  useEffect(() => {
    if (!fillSignal) return;
    // After React wrote the template into the box.
    requestAnimationFrame(() => { if (!selectPlaceholder(0)) ref.current?.focus(); });
  }, [fillSignal]);
  const withContext = context && !dropContext && !mentions.some((m) => m.kind === context.kind && m.id === context.id) ? [context, ...mentions] : mentions;

  const onChange = (v: string) => {
    setText(v);
    const upto = v.slice(0, ref.current?.selectionStart ?? v.length);
    const m = /(?:^|\s)@([^\s@]{0,40})$/.exec(upto);
    setQuery(m ? m[1]! : null);
    setActive(0);
  };
  const pick = (c: MentionCandidateDto) => {
    const el = ref.current;
    const pos = el?.selectionStart ?? text.length;
    setText(`${text.slice(0, pos).replace(/@([^\s@]{0,40})$/, '')}${text.slice(pos)}`);
    if (!mentions.some((m) => m.kind === c.kind && m.id === c.id)) setMentions([...mentions, { kind: c.kind, id: c.id, label: c.label, valid: true }]);
    setQuery(null);
    el?.focus();
  };
  // Pasted, dropped or chosen files; read one batch at a time so the limits count what is already added.
  const addFiles = async (list: File[], fromFolder = false) => {
    if (!list.length || adding) return;
    setAdding(true);
    try {
      const r = await readFiles(list, files, fromFolder);
      setFiles((cur) => [...cur, ...r.added]);
      if (r.errors.length) toast.error(new Error(r.errors.slice(0, 3).join('；') + (r.errors.length > 3 ? ` 等 ${r.errors.length} 个文件` : '')), '无法添加');
      if (r.skipped.length) toast.info(`已跳过 ${r.skipped.length} 个文件（不是图片或文本，或超出大小与数量限制）`);
      if (fromFolder && !r.added.length && !r.skipped.length) toast.info('文件夹中没有可添加的文件');
    } finally { setAdding(false); ref.current?.focus(); }
  };
  const onPaste = (e: ClipboardEvent<HTMLTextAreaElement>) => {
    const pasted = [...e.clipboardData.files];
    if (!pasted.length) return;
    // Copying from an editor may carry both text and a picture of it: the text is what was meant.
    if (e.clipboardData.getData('text/plain')) return;
    e.preventDefault();
    void addFiles(pasted);
  };
  const onDrop = (e: DragEvent<HTMLDivElement>) => {
    setDropping(false);
    if (!e.dataTransfer.files.length) return;
    e.preventDefault();
    void addFiles([...e.dataTransfer.files]);
  };
  const pickFiles = () => { setMenu(false); fileInput.current?.click(); };
  const canSend = !!text.trim() || files.length > 0;
  const send = async () => {
    if (!canSend || busy || streaming || adding) return;
    setBusy(true);
    const ok = await onSend(text.trim(), withContext, files);
    setBusy(false);
    if (ok) { setText(''); setMentions([]); setFiles([]); }
  };
  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'u') { e.preventDefault(); pickFiles(); return; }
    if (query !== null && options.length) {
      if (e.key === 'ArrowDown') { e.preventDefault(); setActive((a) => (a + 1) % options.length); return; }
      if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => (a - 1 + options.length) % options.length); return; }
      if (e.key === 'Enter' || e.key === 'Tab') { e.preventDefault(); pick(options[active]!); return; }
      if (e.key === 'Escape') { setQuery(null); return; }
    }
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); void send(); }
    // Template placeholders: Tab selects the next 【…】 still to fill in.
    if (e.key === 'Tab' && !e.shiftKey && selectPlaceholder(e.currentTarget.selectionEnd)) e.preventDefault();
  };
  return (
    <div className={C.composer} ref={wrap}>
      {query !== null && options.length > 0 && (
        <div className={cx(C.popover, below && C.popoverBelow)} role="listbox" aria-label="引用候选">
          {options.map((c, i) => (
            <button key={`${c.kind}:${c.id}`} role="option" aria-selected={i === active} className={cx(C.option, i === active && C.optionOn)} onMouseDown={(e) => { e.preventDefault(); pick(c); }}>
              <span className={C.optionKind}>{KIND_LABEL[c.kind]}</span><span>{c.label}</span>{c.detail && <span className={C.optionDetail}>{candidateDetail(c)}</span>}
            </button>
          ))}
        </div>
      )}
      {top}
      <div className={cx(C.box, dropping && C.boxDrop)} onDragOver={(e) => { if (e.dataTransfer.types.includes('Files')) { e.preventDefault(); setDropping(true); } }} onDragLeave={() => setDropping(false)} onDrop={onDrop}>
        <PendingFiles files={files} onRemove={(k) => setFiles(files.filter((f) => f.key !== k))} />
        <MentionChips mentions={withContext} onRemove={(m) => { if (context && m.kind === context.kind && m.id === context.id) setDropContext(true); else setMentions(mentions.filter((x) => !(x.kind === m.kind && x.id === m.id))); }} />
        <textarea ref={ref} className={C.input} rows={2} value={text} disabled={disabled} aria-label="输入消息" autoFocus={autoFocus}
          placeholder={placeholder ?? '输入问题，@ 引用项目、审计、漏洞或知识。例如：@V-3 这个越权在网关层有没有防护？'}
          onChange={(e) => onChange(e.target.value)} onKeyDown={onKey} onPaste={onPaste} />
        <div className={C.boxBar}>
          <div className={C.addWrap} ref={menuRef}>
            <Button size="sm" variant="ghost" icon="plus" aria-label="添加文件" aria-haspopup="menu" aria-expanded={menu} loading={adding} disabled={disabled} onClick={() => setMenu(!menu)} />
            {menu && (
              <div className={cx(C.addMenu, below && C.addMenuBelow)} role="menu">
                <button role="menuitem" className={C.option} onClick={pickFiles}><Icon name="paperclip" size={14} />添加文件或图片<span className={C.addKey}>{/Mac/.test(navigator.platform) ? '⌘U' : 'Ctrl+U'}</span></button>
                <button role="menuitem" className={C.option} onClick={() => { setMenu(false); folderInput.current?.click(); }}><Icon name="folder" size={14} />添加文件夹</button>
              </div>
            )}
            <input ref={fileInput} type="file" multiple hidden aria-label="选择文件" onChange={(e) => { void addFiles([...(e.target.files ?? [])]); e.target.value = ''; }} />
            <input ref={folderInput} type="file" multiple hidden aria-label="选择文件夹" {...{ webkitdirectory: '' }} onChange={(e) => { void addFiles([...(e.target.files ?? [])], true); e.target.value = ''; }} />
          </div>
          <Button size="sm" variant="ghost" aria-label="插入引用" onClick={() => { setText(`${text}${text && !text.endsWith(' ') ? ' ' : ''}@`); setQuery(''); ref.current?.focus(); }}>@ 引用</Button>
          <span className={ui.grow} />
          {streaming && onStop
            ? <Button size="sm" icon="stop" onClick={onStop}>停止</Button>
            : <Button size="sm" variant="primary" icon="send" aria-label="发送" disabled={disabled || !canSend || adding} loading={busy} onClick={() => void send()} />}
        </div>
      </div>
      {hint && <div className={C.hint}>Enter 发送 · Shift+Enter 换行 · 可粘贴或拖入图片与文本文件 · 你在对话中的输入是指令；AI 只能给出建议卡片，由你确认后才会生效</div>}
    </div>
  );
}

/**
 * A conversation, or a draft when `cid` is null: the first message creates the conversation (with `context`
 * as its reference) and `onCreated` reports it. `onOpen` shows a vulnerability or audit next to the thread.
 */
export function ConversationThread({ cid, onCreated, onOpen, context, compact, footer, footerAuditId, ensureConversation, onBeforeSend, composerTop, placeholder, suggestions }: {
  cid: string | null; onCreated?: (c: ConversationDto) => void; onOpen?: (panel: string) => void; context?: MentionDto | null; compact?: boolean;
  /** Shown at the end of the thread (e.g. the live audit card). */
  footer?: ReactNode;
  /** The audit the footer shows: its status cards in the replies are not shown again (the conversation it was started from). */
  footerAuditId?: string;
  /** How a draft gets its conversation (default: a new one); e.g. the audit's bound conversation. */
  ensureConversation?: () => Promise<ConversationDto>;
  /** Handle a message before it is sent as a conversation message (e.g. an intervention in a running audit). */
  onBeforeSend?: (text: string) => Promise<'handled' | 'continue' | 'failed'>;
  composerTop?: ReactNode;
  placeholder?: string;
  /** Suggested questions of an empty thread; without them the quick-start templates are shown. */
  suggestions?: string[];
}) {
  const conv = useConversation(cid ?? '', { enabled: !!cid });
  const msgs = useMessages(cid ?? '', { enabled: !!cid });
  const qc = useQueryClient();
  const toast = useToast();
  const { scrollRef, contentRef, pinned, toBottom } = useStickToBottom<HTMLDivElement, HTMLDivElement>();
  const [liveMid, setLiveMid] = useState<string | null>(null);
  const [draft, setDraft] = useState<string | null>(null);
  const [text, setText] = useState('');
  const [fill, setFill] = useState(0);

  const items = useMemo(() => (cid ? msgs.data?.items ?? [] : []), [cid, msgs.data]);
  const streamingMsg = items.find((m) => m.role === 'assistant' && m.status === 'streaming');
  useEffect(() => { if (streamingMsg && liveMid !== streamingMsg.id) setLiveMid(streamingMsg.id); }, [streamingMsg, liveMid]);
  // The list may learn that the reply ended before the stream's `end` arrives: stop showing it as live.
  useEffect(() => { if (liveMid && items.some((m) => m.id === liveMid && m.status !== 'streaming')) setLiveMid(null); }, [items, liveMid]);
  useEffect(() => { toBottom(); }, [cid, toBottom]);

  const refresh = useCallback(() => {
    if (cid) {
      void qc.invalidateQueries({ queryKey: qk.messages(cid) });
      void qc.invalidateQueries({ queryKey: qk.conversation(cid) });
    }
    void qc.invalidateQueries({ queryKey: ['conversations'] });
    void qc.invalidateQueries({ queryKey: ['dashboard'] });
  }, [qc, cid]);
  const onEnd = useCallback(() => { setLiveMid(null); refresh(); }, [refresh]);

  const send = async (content: string, mentions: MentionDto[], files: PendingFile[]) => {
    try {
      // A message with files is always a conversation message: an intervention carries text only.
      if (onBeforeSend && !files.length) {
        const r = await onBeforeSend(content);
        if (r !== 'continue') { toBottom(); return r === 'handled'; }
      }
      let id = cid;
      if (!id && ensureConversation) { const c = await ensureConversation(); id = c.id; onCreated?.(c); }
      if (!id) {
        // A vulnerability or audit the thread is about names the conversation (“关于 V-1 …”, and the AI panel
        // continues it); otherwise the title comes from the first message and references stay on the message.
        const about = context && ['vuln', 'audit'].includes(context.kind) && mentions.some((m) => m.kind === context.kind && m.id === context.id) ? [{ kind: context.kind, id: context.id }] : [];
        const c = await api.post<ConversationDto>('/conversations', { mentions: about });
        id = c.id;
        onCreated?.(c);
      }
      const r = await api.post<{ assistantMessageId: string }>(`/conversations/${id}/messages`, {
        clientMessageId: clientId(), content, mentions: mentions.map((m) => ({ kind: m.kind, id: m.id })),
        ...attachmentsBody(files),
      });
      setLiveMid(r.assistantMessageId);
      toBottom();
      await qc.invalidateQueries({ queryKey: qk.messages(id) });
      void qc.invalidateQueries({ queryKey: ['conversations'] });
      return true;
    } catch (e) { toast.error(e); return false; }
  };
  const stop = async () => { if (liveMid) try { await api.post(`/messages/${liveMid}/stop`); } catch (e) { toast.error(e); } };
  const regenerate = async (m: MessageDto) => {
    try {
      const r = await api.post<{ assistantMessageId: string }>(`/messages/${m.id}/regenerate`);
      setLiveMid(r.assistantMessageId);
      if (cid) await qc.invalidateQueries({ queryKey: qk.messages(cid) });
    } catch (e) { toast.error(e); }
  };
  const edit = async (m: MessageDto, content: string) => {
    try {
      const r = await api.post<{ assistantMessageId: string }>(`/messages/${m.id}/edit`, { clientMessageId: clientId(), content });
      setLiveMid(r.assistantMessageId);
      if (cid) await qc.invalidateQueries({ queryKey: qk.messages(cid) });
      return true;
    } catch (e) { toast.error(e, '无法编辑'); return false; }
  };
  // “存为知识” (draft source 会话回答): an unverified business-knowledge draft for review.
  const save = async (m: MessageDto) => {
    // The conversation's project also when only a repository, audit or vulnerability of it is mentioned (it went to the
    // global layer, read by every project's audits).
    const pid = conv.data?.projectId ?? conv.data?.mentions.find((x) => x.kind === 'project')?.id;
    try {
      const d = await api.post<{ id: string }>('/knowledge/drafts', { layer: pid ? 'project' : 'global', ...(pid ? { projectId: pid } : {}), text: m.content, category: 'business', source: { kind: 'conversation', ref: m.id, label: conv.data?.title ?? '会话回答' } });
      setDraft(d.id);
    } catch (e) { toast.error(e); }
  };

  const lastUser = [...items].reverse().find((m) => m.role === 'user');
  const c = conv.data;
  return (
    <div className={cx(C.wrap, compact && C.compact)}>
      <div className={C.scroll} ref={scrollRef} aria-live="polite">
        <div className={C.thread} ref={contentRef}>
          {c && c.mentions.length > 0 && <div><span className={ui.faint} style={{ fontSize: 12 }}>本会话引用：</span><MentionChips mentions={c.mentions} /></div>}
          {cid && (conv.isLoading || msgs.isLoading) && <Loading rows={4} />}
          {cid && (conv.error || msgs.error) && <ErrorState error={conv.error ?? msgs.error} onRetry={() => { void conv.refetch(); void msgs.refetch(); }} />}
          {(!cid || (msgs.data && items.length === 0)) && (
            <div className={C.empty}>
              <div className={C.avatar} style={{ width: 44, height: 44, borderRadius: 12 }}><Icon name="sparkle" size={20} /></div>
              <b style={{ fontSize: compact ? 16 : 18 }}>有什么可以帮你？</b>
              <p className={ui.muted} style={{ fontSize: 13 }}>{suggestions
                ? '追问漏洞结论、让 AI 查代码取证、发起审计 / 复验 / 风险排查，或配置连接器。输入 @ 引用对象。'
                : '创建项目、威胁建模、发起审计 / 复验 / 风险排查、追问漏洞，或配置连接器。选一个模板开始，填好【】中的内容（Tab 跳到下一处）；AI 给出卡片，由你确认后才执行。'}</p>
              {suggestions
                ? <div className={C.suggest}>{suggestions.map((s) => <button key={s} className={ui.chip} onClick={() => setText(s)}>{s}</button>)}</div>
                : <QuickStart context={context ?? null} onPick={(t) => { setText(t); setFill((n) => n + 1); }} />}
            </div>
          )}
          {items.map((m) => m.role === 'user'
            ? <UserMessage key={m.id} m={m} editable={m.id === lastUser?.id && !liveMid} onEdit={edit} />
            : <AssistantMessage key={m.id} m={m} liveMid={liveMid} onOpen={onOpen} onEnd={onEnd} onRegenerate={(x) => void regenerate(x)} onSave={(x) => void save(x)} footerAuditId={footerAuditId} />)}
          {footer}
        </div>
      </div>
      {!pinned && (
        <div className={C.jumpWrap}>
          <button className={C.jump} onClick={toBottom}><Icon name="chevronDown" size={14} />回到底部</button>
        </div>
      )}
      <div className={C.composerWrap}>
        <Composer text={text} setText={setText} fillSignal={fill} disabled={!!cid && !c} streaming={!!liveMid} onSend={send} onStop={() => void stop()} top={composerTop} placeholder={placeholder} context={context && !c?.mentions.some((m) => m.kind === context.kind && m.id === context.id) ? context : null} hint={!compact} />
      </div>
      <DraftDialog id={draft} onClose={() => setDraft(null)} />
    </div>
  );
}
