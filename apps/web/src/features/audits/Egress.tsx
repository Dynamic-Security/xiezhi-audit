// Outbound records: what each model session of this audit sent to which provider — files read, enterprise
// facts carried, confidential facts withheld, tokens — for compliance review; CSV download.
import { useQuery } from '@tanstack/react-query';
import type { EgressDto } from '@xiezhi/contracts';
import { API, api } from '../../shared/api/client';
import { fmt } from '../../shared/format/messages';
import { Badge, EmptyState, Icon, Loading, cx, ui } from '../../shared/ui';

export function EgressView({ aid, live }: { aid: string; live: boolean }) {
  const q = useQuery({ queryKey: ['audit', aid, 'egress'], queryFn: () => api.get<EgressDto[]>(`/audits/${aid}/egress`), refetchInterval: live ? 10_000 : false });
  if (q.isLoading) return <Loading />;
  const rows = q.data ?? [];
  const providers = [...new Set(rows.map((r) => `${r.provider}/${r.model}${r.endpoint ? ` @ ${r.endpoint}` : ''}`))];
  const withheld = rows.reduce((n, r) => n + r.withheldFacts, 0);
  return (
    <div className={cx(ui.card, ui.cardPad, ui.stack)}>
      <div className={cx(ui.row, ui.wrap)} style={{ gap: 8 }}>
        <b>外发记录</b>
        <span className={ui.faint}>{rows.length} 个模型会话</span>
        {providers.map((p) => <Badge key={p}>{p}</Badge>)}
        {withheld > 0 && <Badge tone="warn">未发送的机密事实 {withheld}</Badge>}
        <span className={ui.grow} />
        {rows.length > 0 && <a className={cx(ui.btn, ui.sm)} href={`${API}/audits/${aid}/egress?format=csv`} download={`egress-${aid}.csv`}><Icon name="download" />下载 CSV</a>}
      </div>
      {rows.length === 0 ? <EmptyState icon="activity" title="还没有外发记录">每个模型会话结束后记录发往的模型服务、涉及的文件与企业事实。</EmptyState> : (
        <div style={{ overflowX: 'auto' }}>
          <table className={ui.table}>
            <thead><tr><th>时间</th><th>步骤</th><th>模型服务</th><th>文件</th><th>企业事实</th><th>未发送机密</th><th>tokens（入/出）</th><th>状态</th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className={ui.mono}>{fmt.time(r.startedAt)}</td>
                  <td className={ui.mono}>{r.step ?? r.kind}</td>
                  <td className={ui.mono} title={r.endpoint ?? ''}>{r.provider}/{r.model}</td>
                  <td title={r.files.map((f) => `${f.repo ? `${f.repo}:` : ''}${f.path}`).join('\n')}>{r.files.length}</td>
                  <td title={r.facts.join('\n')}>{r.facts.length}</td>
                  <td>{r.withheldFacts || ''}</td>
                  <td className={ui.mono}>{fmt.tokens(r.tokens.input)} / {fmt.tokens(r.tokens.output)}</td>
                  <td>{r.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
