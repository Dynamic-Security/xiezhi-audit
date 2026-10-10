// Knowledge building blocks shared by the global knowledge page and the project knowledge tab:
// list by category tabs with override / disabled / invalid marks, skill view,
// editor with live preview and content-hash conflicts, sub-files.
import { useEffect, useState, type ReactNode } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import type { SkillBodyDto, SkillDto, SkillFileDto } from '@xiezhi/contracts';
import { ApiError, api } from '../../shared/api/client';
import { Badge, Button, ConfirmDialog, Dialog, EmptyState, Field, Icon, Loading, Tabs, cx, ui, useToast } from '../../shared/ui';
import { fmt } from '../../shared/format/messages';
import { SkillPreview } from './Markdown';

/** Skill categories in tab order: 安全规范 first, 系统架构 / 业务知识 last (shown only when there are any). */
export const CATEGORY: Record<string, string> = { security_spec: '安全规范', audit_method: '审计方法', vuln_case: '漏洞案例', report: '报告规范', push_guide: '推送指引', architecture: '系统架构', business: '业务知识' };
const ALWAYS_SHOWN = new Set(['security_spec', 'audit_method', 'vuln_case', 'report', 'push_guide']);
const FLOW = '__flow';
const CATEGORY_HINT: Record<string, string> = {
  security_spec: '企业自己的安全规范，例如 KMS 与密钥使用规范、服务间鉴权规范、日志脱敏要求。审计时按需读取，违反规范的写法按漏洞或风险报告。',
  audit_method: '某类漏洞或框架的审计方法：判断要点、成立与不成立条件。',
  vuln_case: '历史漏洞与误报先例，遇到同类模式时参考。',
  report: '报告的结构与措辞规范，只影响措辞与模板，不改变结论。',
  push_guide: '把漏洞或威胁模型推送到外部系统（工单、在线文档）的指引，不进入审计会话。',
  architecture: '系统架构事实，未核实的只能作为推测使用。',
  business: '业务规则事实，未核实的只能作为推测使用。',
};
type Layer = 'global' | 'project';

export const skillPath = (layer: Layer, pid: string | undefined, name: string) => (layer === 'global' ? `/knowledge/global/${name}` : `/projects/${pid}/knowledge/${name}`);

export function useSkill(layer: Layer, pid: string | undefined, name: string | null) {
  return useQuery({ queryKey: ['skill', layer, pid ?? '', name], enabled: !!name, queryFn: () => api.get<SkillBodyDto>(skillPath(layer, pid, name!)) });
}

function useRefresh() {
  const qc = useQueryClient();
  return () => Promise.all([qc.invalidateQueries({ queryKey: ['knowledge'] }), qc.invalidateQueries({ queryKey: ['skill'] })]);
}

const DISABLED_BY: Record<string, string> = { global: '全局已下线', project_name: '本项目已停用', project_category: '本项目已停用该类别' };

export function SkillFlags({ s, projectView }: { s: SkillDto; projectView: boolean }) {
  return (
    <span className={cx(ui.row, ui.wrap)} style={{ gap: 4 }}>
      {projectView && (s.layer === 'project' ? <Badge tone="accent">项目</Badge> : <Badge>全局</Badge>)}
      {s.overridesGlobal && <Badge tone="info" title="与全局同名，本项目以它为准">覆盖全局</Badge>}
      {s.layer === 'global' && s.overriddenBy.length > 0 && <Badge tone="neutral" title={projectView ? '本项目有同名 skill' : `${s.overriddenBy.length} 个项目有同名 skill`}>{projectView ? '已被项目覆盖' : `被 ${s.overriddenBy.length} 个项目覆盖`}</Badge>}
      {s.disabled && <Badge tone="warn">{s.disabledBy.map((d) => DISABLED_BY[d]).join('、')}</Badge>}
      {s.verified === false && <Badge tone="warn" title="未核实的业务知识 / 系统架构只能作为推测使用">未核实</Badge>}
      {!s.valid && <Badge tone="danger" title={s.errors.join('\n')}>无效</Badge>}
      {s.warnings.length > 0 && <Badge tone="warn" title={s.warnings.join('\n')}>提示</Badge>}
    </span>
  );
}

/**
 * The knowledge tabs: the pipeline prompts (`审计流程`, when given) and the skill categories share one
 * tab row, left to right 审计流程 · 安全规范 · 审计方法 · 漏洞案例 · 报告规范 · 推送指引; 系统架构 / 业务知识 and the invalid
 * skills (no category) follow only when there are any. The tab follows the selected skill, so opening one from elsewhere
 * (a new skill, a link) shows its category; so does `reveal` (`layer:name`, an approved draft) without selecting it.
 */
export function SkillGroups({ items, selected, reveal, onSelect, projectView, flow }: {
  items: SkillDto[]; selected?: string | undefined; reveal?: string | undefined; onSelect: (s: SkillDto) => void; projectView: boolean;
  flow?: { count?: number | undefined; content: ReactNode } | undefined;
}) {
  const groups = [...Object.keys(CATEGORY), '__invalid']
    .map((c) => ({ c, items: items.filter((s) => (c === '__invalid' ? !s.category : s.category === c)) }))
    .filter((g) => g.items.length || ALWAYS_SHOWN.has(g.c));
  const focus = selected ?? reveal;
  const found = focus ? items.find((s) => `${s.layer}:${s.name}` === focus) : undefined;
  const selectedCat = found ? (found.category ?? '__invalid') : undefined;
  const [tab, setTab] = useState<string | undefined>(selectedCat);
  useEffect(() => { if (selectedCat) setTab(selectedCat); }, [selectedCat]);
  const tabs = [
    ...(flow ? [{ key: FLOW, label: '审计流程', count: flow.count }] : []),
    ...groups.map((x) => ({ key: x.c, label: x.c === '__invalid' ? '无效（需要修复）' : CATEGORY[x.c]!, count: x.items.length })),
  ];
  const current = tabs.find((t) => t.key === tab) ?? tabs[0]!;
  const g = groups.find((x) => x.c === current.key);
  return (
    <section style={{ marginTop: 20 }}>
      <Tabs value={current.key} onChange={setTab} items={tabs} />
      {current.key === FLOW ? <div role="tabpanel" aria-label="审计流程" style={{ marginTop: 12 }}>{flow!.content}</div> : g && (
        <div role="tabpanel" aria-label={current.label} style={{ marginTop: 12 }}>
          {CATEGORY_HINT[g.c] && <p className={ui.faint} style={{ fontSize: 12, margin: '0 0 8px' }}>{CATEGORY_HINT[g.c]}</p>}
          {!g.items.length ? <div className={ui.card}><EmptyState icon="book" title={`还没有${current.label}`}>点击右上角“新建{projectView ? '项目' : ''} skill”，类别选“{current.label}”；也可以用“导入 / 粘贴”让 AI 整理现有文档。</EmptyState></div> : (
            <div className={ui.card} style={{ overflow: 'auto' }}>
              <table className={ui.table}>
                <tbody>{g.items.map((s) => (
                  <tr key={`${s.layer}:${s.name}`} className={cx(ui.rowLink, selected === `${s.layer}:${s.name}` && ui.rowSel)} style={s.disabled || (projectView && s.layer === 'global' && s.overriddenBy.length) ? { opacity: 0.6 } : undefined} onClick={() => onSelect(s)}>
                    <td>
                      <div className={ui.row} style={{ gap: 8 }}><b>{s.name}</b><SkillFlags s={s} projectView={projectView} /></div>
                      <div className={ui.faint} style={{ fontSize: 12 }}>{s.valid ? s.description : s.errors.join('；')}</div>
                    </td>
                    <td className={ui.mono} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{s.category === 'push_guide' ? '' : s.load ?? ''}</td>
                    <td className={ui.faint} style={{ fontSize: 12, whiteSpace: 'nowrap' }}>{s.updatedAt ? fmt.ago(s.updatedAt) : ''}</td>
                  </tr>
                ))}</tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function template(name: string, category: string, layer: Layer): string {
  if (category === 'push_guide') {
    return `---\nname: ${name || 'new-push-guide'}\ndescription: 一句话写清推送到哪个系统、做成什么（20–400 字）\ncategory: push_guide\nscope: ${layer}\npush:\n  connector: 连接器名称\n  operation: 写操作名称\n  external_id: $.key\n  confirm: false\n---\n# 推送指引\n\n写明字段映射与措辞要求。添加子文件 template.yaml（{{title}} 等占位符）可确定性渲染参数；没有模板时由对话模型按本指引填写。\n`;
  }
  if (category === 'security_spec') {
    return `---\nname: ${name || 'new-security-spec'}\ndescription: 一句话写清“这是哪条企业安全规范、审计什么代码时加载”（20–400 字）\ncategory: security_spec\nscope: ${layer}\nload: on_demand\n---\n# 规范名称\n\n## 规范要求\n\n## 违反的判定\n\n## 合规写法 / 例外\n`;
  }
  const fact = category === 'business' || category === 'architecture';
  return `---\nname: ${name || 'new-skill'}\ndescription: 一句话写清“这是什么、什么时候加载”（20–400 字）\ncategory: ${category}\nscope: ${layer}\nload: on_demand\n${fact ? 'source: "user:"\nverified: false\n' : ''}---\n# 标题\n\n## 判断要点\n\n## 成立条件 / 不成立条件\n`;
}

/** Replace the `scope:` line (copying a global skill into a project). */
export function withScope(text: string, layer: Layer): string {
  return /^(---\r?\n[\s\S]*?)^scope:.*$/m.test(text) ? text.replace(/^scope:.*$/m, `scope: ${layer}`) : text.replace(/^---\r?\n/, `---\nscope: ${layer}\n`);
}

/**
 * Editor with live preview. Saving sends the entry hash it started from; a 412 shows the disk version
 * next to the editor so the user can merge and save again on top of it.
 */
export function SkillEditor({ open, onClose, layer, pid, name, initial, onSaved }: {
  open: boolean; onClose: () => void; layer: Layer; pid?: string | undefined; name: string | null;
  initial?: { text: string; base: string | null; form?: 'file' | 'dir' }; onSaved?: (d: SkillBodyDto) => void;
}) {
  const refresh = useRefresh();
  const toast = useToast();
  const creating = !name || initial?.base === null;
  const [newName, setNewName] = useState('');
  const [category, setCategory] = useState('audit_method');
  const [form, setForm] = useState<'file' | 'dir'>('file');
  const [text, setText] = useState('');
  const [touched, setTouched] = useState(false);
  const [base, setBase] = useState<string | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [conflict, setConflict] = useState<{ sha256: string | null; text: string | null } | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!open) return;
    setText(initial?.text ?? template('', 'audit_method', layer));
    setBase(initial?.base ?? null);
    setForm(initial?.form ?? 'file');
    setNewName(name ?? '');
    setTouched(!!initial);
    setErrors([]);
    setConflict(null);
  }, [open, initial, layer, name]);
  useEffect(() => {
    if (open && !name && !touched) setText(template(newName, category, layer));
  }, [open, name, touched, newName, category, layer]);
  const target = name ?? newName;
  const save = async () => {
    setBusy(true);
    setErrors([]);
    try {
      const d = await api.put<SkillBodyDto>(skillPath(layer, pid, target), { text, baseSha256: base, ...(creating ? { form } : {}) });
      toast.ok(creating ? '已创建' : '已保存');
      await refresh();
      onSaved?.(d);
      onClose();
    } catch (e) {
      if (e instanceof ApiError && e.status === 412) setConflict((e.details?.current as { sha256: string | null; text: string | null }) ?? { sha256: null, text: null });
      else if (e instanceof ApiError && e.status === 422) setErrors((e.details?.errors as string[]) ?? [e.hint ?? e.message]);
      else toast.error(e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onClose={onClose} wide="xl" title={creating ? `新建${layer === 'global' ? '全局' : '项目'} skill` : `编辑 ${name}`} footer={<>
      {errors.length > 0 && <div role="alert" className={ui.error} style={{ marginRight: 'auto', maxWidth: '70%' }}>{errors.join('；')}</div>}
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!target} onClick={() => void save()}>{conflict ? '以当前内容保存' : '保存'}</Button>
    </>}>
      {creating && !name && (
        <div className={ui.row} style={{ gap: 12, alignItems: 'flex-end' }}>
          <Field label="名称" hint="小写字母、数字、连字符；同一层内唯一"><input className={ui.input} value={newName} onChange={(e) => setNewName(e.target.value.trim())} placeholder="spring-order-idor" autoFocus /></Field>
          <Field label="类别"><select className={ui.input} value={category} onChange={(e) => setCategory(e.target.value)}>{Object.entries(CATEGORY).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></Field>
          <Field label="形态"><select className={ui.input} value={form} onChange={(e) => setForm(e.target.value as 'file' | 'dir')}><option value="file">单文件</option><option value="dir">目录（可带子文件）</option></select></Field>
        </div>
      )}
      {conflict && (
        <div className={ui.banner} role="alert">
          文件已在别处被修改（可能是外部编辑器或 Git）。下方右侧是磁盘上的当前版本：把需要的内容合并到左侧后再保存；或
          <Button size="sm" variant="ghost" onClick={() => { setText(conflict.text ?? ''); setBase(conflict.sha256); setConflict(null); }}>放弃我的修改，使用磁盘版本</Button>
          <Button size="sm" variant="ghost" onClick={() => { setBase(conflict.sha256); setConflict({ ...conflict }); }}>基于磁盘版本保存我的内容</Button>
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: conflict ? '1fr 1fr 1fr' : '1fr 1fr', gap: 12, minHeight: '55vh' }}>
        <textarea aria-label="skill 内容" className={cx(ui.textarea, ui.mono)} style={{ minHeight: '55vh', fontSize: 12.5 }} value={text} onChange={(e) => { setText(e.target.value); setTouched(true); }} spellCheck={false} />
        <div className={ui.card} style={{ padding: 14, overflow: 'auto', maxHeight: '62vh' }} aria-label="预览"><SkillPreview text={text} /></div>
        {conflict && <pre className={cx(ui.card, ui.mono, ui.pre)} style={{ padding: 12, margin: 0, fontSize: 12, overflow: 'auto', maxHeight: '62vh' }} aria-label="磁盘版本">{conflict.text ?? '（磁盘上已删除）'}</pre>}
      </div>
      <p className={ui.faint} style={{ fontSize: 12, margin: 0 }}>文件头必须包含 name、description、category；业务知识与系统架构还需要 source 与 verified。保存时校验，不合格的内容不会写入磁盘。</p>
    </Dialog>
  );
}

function SubFileDialog({ open, onClose, layer, pid, name, path }: { open: boolean; onClose: () => void; layer: Layer; pid?: string | undefined; name: string; path: string | null }) {
  const refresh = useRefresh();
  const toast = useToast();
  const q = useQuery({ queryKey: ['skill-file', layer, pid ?? '', name, path], enabled: open && !!path, queryFn: () => api.get<SkillFileDto>(`${skillPath(layer, pid, name)}/files/${path}`) });
  const [newPath, setNewPath] = useState('');
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (open) { setText(q.data?.text ?? ''); setNewPath(''); } }, [open, q.data]);
  const target = path ?? newPath;
  const save = async () => {
    setBusy(true);
    try {
      await api.put(`${skillPath(layer, pid, name)}/files/${target}`, { text, baseSha256: path ? q.data?.sha256 ?? null : null });
      toast.ok('已保存');
      await refresh();
      onClose();
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  const remove = async () => {
    setBusy(true);
    try {
      await api.del(`${skillPath(layer, pid, name)}/files/${path}?baseSha256=${q.data?.sha256}`);
      toast.ok('已删除');
      await refresh();
      onClose();
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <Dialog open={open} onClose={onClose} wide title={path ? `${name}/${path}` : `为 ${name} 添加子文件`} footer={<>
      {path && <Button variant="danger" icon="trash" loading={busy} onClick={() => void remove()} style={{ marginRight: 'auto' }}>删除</Button>}
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" loading={busy} disabled={!target} onClick={() => void save()}>保存</Button>
    </>}>
      {!path && <Field label="文件路径" hint="相对 skill 目录，例如 idor-order-2025.md 或 examples/Bad.java"><input className={ui.input} value={newPath} onChange={(e) => setNewPath(e.target.value.trim())} autoFocus /></Field>}
      {path && q.isLoading ? <Loading /> : <textarea aria-label="文件内容" className={cx(ui.textarea, ui.mono)} style={{ minHeight: '50vh', fontSize: 12.5 }} value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} />}
    </Dialog>
  );
}

/**
 * One skill: marks, actions (edit, delete, disable in this scope, copy a global skill into the project)
 * and the rendered body with its files.
 */
export function SkillView({ item, pid, onDeleted, onMoveToGlobal }: { item: SkillDto; pid?: string | undefined; onDeleted?: () => void; onMoveToGlobal?: (name: string) => void }) {
  const layer = item.layer as Layer;
  const q = useSkill(layer, layer === 'project' ? pid : undefined, item.name);
  const refresh = useRefresh();
  const toast = useToast();
  const [edit, setEdit] = useState<{ text: string; base: string | null } | null>(null);
  const [copy, setCopy] = useState<{ text: string; base: null } | null>(null);
  const [file, setFile] = useState<string | null | undefined>(undefined);
  const [del, setDel] = useState(false);
  const [busy, setBusy] = useState(false);
  const projectView = !!pid;
  const toggle = async () => {
    setBusy(true);
    try {
      if (projectView) await api.put(`/projects/${pid}/knowledge-overrides/${item.name}`, { disabled: !item.disabledBy.includes('project_name') });
      else await api.put(`/knowledge/global-overrides/${item.name}`, { disabled: !item.disabled });
      await refresh();
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  if (q.isLoading) return <Loading rows={8} />;
  if (!q.data) return <EmptyState title="无法读取" />;
  const d = q.data;
  const disabledHere = projectView ? item.disabledBy.includes('project_name') : item.disabledBy.includes('global');
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: 16 }}>
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
        <SkillFlags s={item} projectView={projectView} />
        {d.category && <Badge>{CATEGORY[d.category] ?? d.category}</Badge>}
        {d.load && d.category !== 'push_guide' && <Badge tone="neutral">{d.load}</Badge>}
        <span className={ui.faint} style={{ fontSize: 12 }}>更新于 {fmt.ago(d.updatedAt)}</span>
      </div>
      {!d.valid && <div className={ui.banner} role="alert">无效：{d.errors.join('；')}。修复前不会被任何审计加载。</div>}
      {d.warnings.map((w) => <div key={w} className={ui.faint} style={{ fontSize: 12 }}>提示：{w}</div>)}
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 6 }}>
        <Button size="sm" icon="edit" onClick={() => setEdit({ text: d.body, base: d.entrySha256 })}>编辑</Button>
        {(projectView || item.layer === 'global') && (
          <Button size="sm" loading={busy} onClick={() => void toggle()}>{disabledHere ? (projectView ? '在本项目恢复' : '恢复上线') : (projectView ? '在本项目停用' : '全局下线')}</Button>
        )}
        {projectView && item.layer === 'global' && item.overriddenBy.length === 0 && (
          <Button size="sm" icon="plus" onClick={() => setCopy({ text: withScope(d.body, 'project'), base: null })}>复制到项目并修改</Button>
        )}
        {d.valid && <Button size="sm" icon="plus" onClick={() => setFile(null)}>添加子文件</Button>}
        {projectView && layer === 'project' && d.valid && d.form === 'file' && onMoveToGlobal && <Button size="sm" onClick={() => onMoveToGlobal(item.name)}>移到全局</Button>}
        {item.layer === 'global' && d.valid && d.category !== 'push_guide' && <Link to="/hunts/new" search={{ skill: d.name }} className={ui.chip}><Icon name="target" size={12} />用它排查</Link>}
        <Button size="sm" variant="danger" icon="trash" onClick={() => setDel(true)} style={{ marginLeft: 'auto' }}>删除</Button>
      </div>
      {d.files.length > 1 && (
        <div className={ui.card} style={{ padding: '6px 10px' }}>
          {d.files.filter((f) => f.path !== d.entryFile).map((f) => (
            <button key={f.path} className={ui.menuItem} onClick={() => setFile(f.path)} style={{ width: '100%' }}><Icon name="file" size={12} /><span className={ui.mono} style={{ fontSize: 12 }}>{f.path}</span><span className={ui.faint} style={{ marginLeft: 'auto', fontSize: 12 }}>{fmt.bytes(f.size)}</span></button>
          ))}
        </div>
      )}
      <SkillPreview text={d.body} />
      <SkillEditor open={!!edit} onClose={() => setEdit(null)} layer={layer} pid={pid} name={item.name} {...(edit ? { initial: edit } : {})} />
      <SkillEditor open={!!copy} onClose={() => setCopy(null)} layer="project" pid={pid} name={item.name} {...(copy ? { initial: copy } : {})} />
      <SubFileDialog open={file !== undefined} onClose={() => setFile(undefined)} layer={layer} pid={pid} name={item.name} path={file ?? null} />
      <ConfirmDialog open={del} onClose={() => setDel(false)} level="destructive" typeToConfirm={item.name} title={`删除 ${item.layer === 'global' ? '全局' : '项目'} skill ${item.name}？`} confirmText="删除" loading={busy} onConfirm={async () => {
        setBusy(true);
        try {
          await api.del(`${skillPath(layer, pid, item.name)}?baseSha256=${d.entrySha256}`);
          toast.ok('已删除');
          setDel(false);
          await refresh();
          onDeleted?.();
        } catch (e) { toast.error(e); } finally { setBusy(false); }
      }}>文件会从知识目录中删除（用 Git 管理的目录可以找回）。正在运行的审计使用审计开始时冻结的内容，不受影响。</ConfirmDialog>
    </div>
  );
}

