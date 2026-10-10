// 从已有配置导入: MCP servers already configured in Cursor, Claude Code, Claude Desktop, Gemini CLI or
// Windsurf become connectors. Credentials are shown masked; per credential the person chooses to copy it into the
// local secret store, fill it in later, or drop the argument. The command is then confirmed and tested as usual.
import { useEffect, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { McpImportCandidateDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { Badge, Button, Dialog, EmptyState, Field, Loading, cx, ui, useToast } from '../../shared/ui';

/** Tools the built-in Feishu guides use (feishu-doc-read, feishu-doc-threat-model-sync). */
const LARK_TOOLS = 'docx.v1.document.rawContent,wiki.v2.space.getNode,docx.builtin.import,docx.v1.document.convert,docx.v1.documentBlockChildren.get,docx.v1.documentBlockChildren.batchDelete,docx.v1.documentBlockDescendant.create,drive.v1.permissionMember.create';
type Choice = 'import' | 'blank' | 'drop';
const CHOICE: Record<Choice, string> = { import: '复制到本机密钥', blank: '稍后填写', drop: '去掉该参数' };

const isLark = (c: McpImportCandidateDto) => c.args.some((a) => a.includes('lark-mcp'));
/** A user access token expires within hours: dropping it (the app identity is used) is the safer default. */
const defaultChoice = (c: McpImportCandidateDto, s: McpImportCandidateDto['secrets'][number]): Choice =>
  s.where === 'arg' && (/^-u$|user/i.test(s.key)) ? 'drop' : 'import';

export function ImportMcpDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const q = useQuery({ queryKey: ['connector-imports'], enabled: open, queryFn: () => api.get<McpImportCandidateDto[]>('/connector-imports') });
  const [picked, setPicked] = useState<McpImportCandidateDto | null>(null);
  const [name, setName] = useState('');
  const [choices, setChoices] = useState<Record<string, Choice>>({});
  const [extra, setExtra] = useState('');
  const [busy, setBusy] = useState(false);
  const toast = useToast();
  const qc = useQueryClient();
  useEffect(() => {
    if (!picked) return;
    const lark = isLark(picked);
    setName(lark ? 'Feishu' : picked.name);
    setChoices(Object.fromEntries(picked.secrets.map((s) => [s.name, defaultChoice(picked, s)])));
    setExtra(lark && !picked.args.includes('-t') && !picked.args.includes('--tools') ? `-t\n${LARK_TOOLS}` : '');
  }, [picked]);
  const close = () => { setPicked(null); onClose(); };
  const submit = async () => {
    if (!picked) return;
    setBusy(true);
    try {
      await api.post('/connector-imports', {
        candidate: picked.id, name: name.trim(), secrets: choices,
        extraArgs: extra.split('\n').map((x) => x.trim()).filter(Boolean),
      });
      toast.ok('已导入：请在连接器中确认命令并测试连接');
      await qc.invalidateQueries({ queryKey: ['connectors'] });
      close();
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <Dialog open={open} onClose={close} wide title="从已有配置导入 MCP" footer={<>
      <Button onClick={picked ? () => setPicked(null) : close}>{picked ? '返回' : '取消'}</Button>
      {picked && <Button variant="primary" loading={busy} disabled={!name.trim() || (picked.protocol === 'mcp_stdio' && !picked.resolvedPath)} onClick={() => void submit()}>导入</Button>}
    </>}>
      {!picked ? (
        q.isLoading ? <Loading /> : !q.data?.length ? (
          <EmptyState icon="link" title="没有找到已配置的 MCP">读取 Cursor（~/.cursor/mcp.json）、Claude Code（~/.claude.json）、Claude Desktop、Gemini CLI、Windsurf 的配置文件。</EmptyState>
        ) : (
          <>
            <p className={ui.muted} style={{ margin: 0 }}>从本机其他工具的 MCP 配置导入。凭证只显示掩码，导入时由你决定是否复制到本机密钥；导入后仍需确认命令并测试连接。</p>
            <table className={ui.table}>
              <thead><tr><th>来源</th><th>名称</th><th>命令或地址</th><th /></tr></thead>
              <tbody>
                {q.data.map((c) => (
                  <tr key={c.id}>
                    <td style={{ whiteSpace: 'nowrap' }}>{c.sourceLabel}</td>
                    <td><b>{c.name}</b>{c.secrets.length > 0 && <> <Badge tone="warn">{c.secrets.length} 个凭证</Badge></>}</td>
                    <td className={ui.mono} style={{ fontSize: 12, wordBreak: 'break-all' }}>
                      {c.protocol === 'mcp_stdio' ? `${c.command} ${c.args.join(' ')}` : c.url}
                      {c.issues.map((x) => <div key={x} className={ui.faint}>{x}</div>)}
                    </td>
                    <td><Button size="sm" onClick={() => setPicked(c)}>选择</Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </>
        )
      ) : (
        <div className={ui.stack}>
          <div className={cx(ui.mono, ui.faint)} style={{ fontSize: 12, wordBreak: 'break-all' }}>
            {picked.sourceLabel} · {picked.sourcePath}<br />{picked.protocol === 'mcp_stdio' ? `${picked.resolvedPath ?? picked.command} ${picked.args.join(' ')}` : picked.url}
          </div>
          {picked.issues.map((x) => <div key={x} className={ui.banner}>{x}</div>)}
          <div className={cx(ui.row, ui.wrap)} style={{ gap: 12 }}>
            <Field label="连接器名称" hint={isLark(picked) ? '内置飞书指引使用名称 Feishu' : undefined}><input className={ui.input} value={name} maxLength={100} onChange={(e) => setName(e.target.value)} /></Field>
          </div>
          {picked.secrets.length > 0 && (
            <Field group label="凭证">
              <table className={ui.table}>
                <tbody>
                  {picked.secrets.map((s) => (
                    <tr key={s.name}>
                      <td className={ui.mono} style={{ fontSize: 12 }}>{s.where === 'arg' ? '参数' : s.where === 'env' ? '环境变量' : s.where === 'query' ? '地址参数' : '请求头'} {s.key}</td>
                      <td className={ui.mono} style={{ fontSize: 12 }}>{s.masked}</td>
                      <td>
                        <select className={ui.input} aria-label={`凭证 ${s.key}`} value={choices[s.name] ?? 'import'} onChange={(e) => setChoices({ ...choices, [s.name]: e.target.value as Choice })}>
                          {(Object.keys(CHOICE) as Choice[]).filter((k) => k !== 'drop' || s.where !== 'header').map((k) => <option key={k} value={k}>{CHOICE[k]}</option>)}
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <span className={ui.faint} style={{ fontSize: 12 }}>凭证写成 <code>{'${secret:名称}'}</code>，值只保存在本机配置文件中，不出现在页面、日志或模型上下文里。用户令牌（如 <code>-u</code>）通常数小时内过期，默认去掉、改用应用身份。</span>
            </Field>
          )}
          <Field label="追加参数（每行一个，可选）" hint={isLark(picked) ? '已预填内置飞书指引需要的工具列表（-t）' : undefined}>
            <textarea className={cx(ui.textarea, ui.mono)} style={{ fontSize: 12 }} value={extra} onChange={(e) => setExtra(e.target.value)} />
          </Field>
        </div>
      )}
    </Dialog>
  );
}
