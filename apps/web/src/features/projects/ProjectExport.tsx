// Project-level export: every active vulnerability of the project across
// audits (or the selected ones), rendered by the same report pipeline as an audit export. The file is
// produced on request and downloaded directly (GET, same-origin session).
import { useState } from 'react';
import { API } from '../../shared/api/client';
import { qs } from '../../shared/api/queries';
import { Button, Dialog, Field, Icon, Segmented, cx, ui } from '../../shared/ui';

type Format = 'md' | 'html' | 'json' | 'sarif';

export function projectExportUrl(pid: string, o: { format: Format; vulnIds?: string[]; includePending: boolean; snippets: boolean; localRoots: boolean }): string {
  return `${API}/projects/${pid}/export${qs({
    format: o.format, vulnIds: o.vulnIds, includePending: o.includePending ? undefined : '0',
    ...(o.format === 'sarif' ? { snippets: o.snippets ? '1' : '0', localRoots: o.localRoots ? '1' : '0' } : {}),
  })}`;
}

export function ProjectExportDialog({ pid, open, onClose, selected }: {
  pid: string; open: boolean; onClose: () => void;
  /** Vulnerabilities selected in the list; offered as the default scope when present. */
  selected?: { id: string; displayNo: number }[];
}) {
  const [format, setFormat] = useState<Format>('html');
  const [scope, setScope] = useState<'all' | 'picked'>(selected?.length ? 'picked' : 'all');
  const [includePending, setIncludePending] = useState(true);
  const [snippets, setSnippets] = useState(true);
  const [localRoots, setLocalRoots] = useState(true);
  const picked = scope === 'picked' && selected?.length ? selected : null;
  const href = projectExportUrl(pid, { format, ...(picked ? { vulnIds: picked.map((v) => v.id) } : {}), includePending, snippets, localRoots });
  return (
    <Dialog open={open} onClose={onClose} title="导出项目漏洞" footer={<>
      <Button onClick={onClose}>关闭</Button>
      <a className={cx(ui.btn, ui.primary)} href={href} download><Icon name="download" />下载 {format === 'md' ? 'Markdown' : format.toUpperCase()}</a>
    </>}>
      <Segmented value={format} onChange={setFormat} items={[{ key: 'html', label: 'HTML' }, { key: 'md', label: 'Markdown' }, { key: 'json', label: 'JSON' }, { key: 'sarif', label: 'SARIF' }]} />
      <p className={ui.muted} style={{ fontSize: 13 }}>
        以漏洞为单位汇总项目内所有审计的结果：确认、处理与跨审计状态取漏洞的当前值，位置与四层详情取每个漏洞最近一次审计中的发现。{format === 'sarif' ? '代码片段取该次审计的快照。' : ''}
      </p>
      {selected && selected.length > 0 && (
        <Field group label="范围">
          <Segmented value={scope} onChange={setScope} items={[{ key: 'all', label: '项目内全部活跃漏洞' }, { key: 'picked', label: `选中的 ${selected.length} 个漏洞` }]} />
        </Field>
      )}
      <label className={ui.checkbox}><input type="checkbox" checked={includePending} onChange={(e) => setIncludePending(e.target.checked)} />包含待确认项</label>
      {format === 'sarif' && <label className={ui.checkbox}><input type="checkbox" checked={snippets} onChange={(e) => setSnippets(e.target.checked)} />包含代码片段</label>}
      {format === 'sarif' && <label className={ui.checkbox}><input type="checkbox" checked={localRoots} onChange={(e) => setLocalRoots(e.target.checked)} />写入本机绝对路径（便于本机 IDE 直接定位；分享给同事时取消）</label>}
      {format === 'sarif' && <div className={ui.banner} style={{ background: 'var(--warn-soft)', color: 'var(--warn)' }}><Icon name="alert" />SARIF 保留被审代码原文，文件可能包含代码中的明文密钥。</div>}
    </Dialog>
  );
}
