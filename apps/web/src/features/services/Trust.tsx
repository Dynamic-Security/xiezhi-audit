// Internal trust and service responsibility (23, 37): the project's setting (inferred from the topology
// when unset) and each service's responsibility card — inbound exposure through the gateways, the upstream guarantees
// recorded as facts, outbound calls.
import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import type { ProjectDto, ServiceCardDto } from '@xiezhi/contracts';
import { api } from '../../shared/api/client';
import { Badge, Button, Dialog, Loading, cx, ui, useToast } from '../../shared/ui';

export const TRUST: Record<string, [string, string]> = {
  zero_trust: ['零信任', '每个服务自己校验；服务间风险照常作为漏洞发布'],
  gateway_boundary: ['网关为边界', '经网关的请求视为已认证；只能从内部到达的服务间风险降一级发布'],
  trusted_network: ['内网可信', '内网调用互信；服务间风险作为提示列出，不发布为漏洞'],
  monolith: ['单体', '不区分服务边界'],
};
export const BOUNDARY: Record<string, string> = { own: '本服务缺陷', upstream: '依赖上游假设', cross_service: '服务间风险' };

export function InternalTrust({ project }: { project: ProjectDto }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const t = project.internalTrust;
  const set = async (v: string) => {
    setBusy(true);
    try {
      await api.patch(`/projects/${project.id}`, { internalTrust: v === 'auto' ? null : v });
      toast.ok('已保存，下一次审计按新的设置处理服务间风险');
      await qc.invalidateQueries({ queryKey: ['project', project.id] });
      await qc.invalidateQueries({ queryKey: ['projects'] });
    } catch (e) { toast.error(e); } finally { setBusy(false); }
  };
  return (
    <section className={cx(ui.card, ui.cardPad)} aria-label="内部信任" style={{ marginTop: 16 }}>
      <div className={ui.spread} style={{ gap: 12, alignItems: 'flex-start' }}>
        <div>
          <b>内部信任</b> <Badge tone="info">{TRUST[t.effective]?.[0] ?? t.effective}</Badge>{t.setting ? null : <span className={ui.faint} style={{ fontSize: 12 }}>（自动：{t.reason}）</span>}
          <div className={ui.faint} style={{ fontSize: 12, marginTop: 4 }}>{TRUST[t.effective]?.[1]}。审计把发现分为本服务缺陷、依赖上游假设、服务间风险三类，服务间风险按这里的设置处理。</div>
        </div>
        <select className={ui.input} style={{ width: 180 }} aria-label="内部信任设置" disabled={busy} value={t.setting ?? 'auto'} onChange={(e) => void set(e.target.value)}>
          <option value="auto">自动（按拓扑推断）</option>
          <option value="zero_trust">零信任</option>
          <option value="gateway_boundary">网关为边界</option>
          <option value="trusted_network">内网可信</option>
        </select>
      </div>
    </section>
  );
}

export function ServiceCardDialog({ pid, repo, onClose }: { pid: string; repo: string; onClose: () => void }) {
  const q = useQuery({ queryKey: ['service-card', pid, repo], queryFn: () => api.get<ServiceCardDto>(`/projects/${pid}/services/${encodeURIComponent(repo)}/card`) });
  const c = q.data;
  return (
    <Dialog open onClose={onClose} wide title={`责任卡 · ${repo}`} footer={<Button onClick={onClose}>关闭</Button>}>
      {!c ? <Loading /> : (
        <div className={ui.stack} style={{ gap: 12 }}>
          <div className={ui.faint} style={{ fontSize: 12 }}>内部信任：{TRUST[c.trust.value]?.[0] ?? c.trust.value}（{c.trust.reason}）· 入口：{Object.entries(c.inbound.channels).map(([k, n]) => `${k} ${n}`).join('、') || '未识别'}</div>
          <section aria-label="经网关暴露的入口">
            <h3 style={{ fontSize: 14 }}>经网关暴露的入口（{c.inbound.exposed.length}）</h3>
            {c.inbound.exposed.length ? <ul style={{ margin: 0, paddingLeft: 18 }}>{c.inbound.exposed.map((x) => <li key={x.entryKey}><code>{x.entryKey}</code> ← {x.routes.map((r) => `${r.gateway} ${r.pathTemplate}${r.auth ? `（经鉴权：${r.auth}）` : '（不经鉴权）'}`).join('；')}</li>)}</ul> : <p className={ui.faint}>没有网关路由转发到这个服务。</p>}
          </section>
          <section aria-label="只能从内部到达的入口">
            <h3 style={{ fontSize: 14 }}>只能从内部到达的入口（{c.inbound.internal.length}）</h3>
            {c.inbound.internal.length ? <p style={{ margin: 0 }}>{c.inbound.internal.map((e) => <code key={e} style={{ marginRight: 8 }}>{e}</code>)}</p> : <p className={ui.faint}>无</p>}
          </section>
          <section aria-label="上游保证">
            <h3 style={{ fontSize: 14 }}>上游保证（企业事实）</h3>
            {c.guarantees.length ? <ul style={{ margin: 0, paddingLeft: 18 }}>{c.guarantees.map((g) => <li key={g.id}><Badge tone={g.trust === 'unverified' ? 'warn' : 'ok'}>{g.trust === 'unverified' ? '未核实' : g.trust === 'authoritative' ? '权威' : '已核实'}</Badge> {g.statement}</li>)}</ul>
              : <p className={ui.faint}>还没有登记。可以在“企业事实”标签中为这个服务登记上游保证（如网关已鉴权、已校验租户），审计会据此区分本服务缺陷与依赖上游的假设。</p>}
          </section>
          <section aria-label="出站调用">
            <h3 style={{ fontSize: 14 }}>出站调用</h3>
            <p style={{ margin: 0 }}>{c.outbound.map((o) => `${o.to}（${o.protocol}）`).join('、') || '无'}</p>
          </section>
        </div>
      )}
    </Dialog>
  );
}
