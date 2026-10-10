// The requirement threat-model report (skill threat-model-report-template): deterministic Markdown from the
// current rows, used for export and as the body pushed to online documents. Statuses are rendered as they are now.
import type { ThreatModelDto, ThreatRiskStatus } from '@xiezhi/contracts';
import type { Store } from '@xiezhi/store';
import { threatModelDetail } from './queries/threat-models.js';
import { AppError } from '@xiezhi/contracts';

export const RISK_STATUS_LABEL: Record<ThreatRiskStatus, string> = {
  pending: '待研判', to_mitigate: '需规避', mitigated: '已规避', accepted: '接受风险', false_positive: '误报 / 不适用',
};
const LEVEL_LABEL: Record<string, string> = { high: '高', medium: '中', low: '低' };
const KIND_LABEL: Record<string, string> = { upload: '上传文档', online: '在线文档', text: '文字描述' };
/** As the workbench shows them (the report is read by people and pushed to online documents). */
export const RISK_CATEGORY_LABEL: Record<string, string> = {
  spoofing: '身份仿冒', tampering: '篡改', repudiation: '抵赖', information_disclosure: '信息泄露', denial_of_service: '拒绝服务',
  elevation_of_privilege: '权限提升', business_logic: '业务逻辑', abuse: '滥用',
};
/** `2026-10-08 22:39` in the service's local time (the report is read next to the workbench, which shows local time). */
export function localTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
const cell = (t: string | null | undefined) => (t ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, '<br>');

export function threatModelMarkdown(d: ThreatModelDto): string {
  const counts = Object.entries(d.riskCounts).filter(([, n]) => n > 0).map(([k, n]) => `${RISK_STATUS_LABEL[k as ThreatRiskStatus]} ${n}`).join('，') || '无';
  const lines = [
    `# ${d.title}`,
    '',
    `- 生成时间：${d.generatedAt ? localTime(d.generatedAt) : '未生成'}${d.status === 'partial' ? '（结果不完整）' : ''}`,
    `- 风险：共 ${d.risks.length} 条（${counts}）`,
    `- 澄清：${d.clarifiedAt ? `已确认（${localTime(d.clarifiedAt)}）` : '未确认'}`,
    `- 来源：${d.sources.map((s) => `S${s.no} ${s.title}（${KIND_LABEL[s.kind]}${s.kind === 'online' && s.fetchStatus === 'failed' ? '，读取失败' : ''}）`).join('；') || '无'}`,
    '',
    '## 功能澄清',
    '',
    (d.clarification ?? '（尚未生成）').replace(/^## /gm, '### '),
    '',
    '## 风险清单',
    '',
    '| 编号 | 等级 | 类别 | 风险 | 影响 | 规避建议 | 状态 | 研判理由 | 来源 |',
    '| --- | --- | --- | --- | --- | --- | --- | --- | --- |',
    ...d.risks.map((r) => `| ${r.code}${r.stale ? '（本次未提出）' : ''} | ${LEVEL_LABEL[r.level ?? ''] ?? '-'} | ${RISK_CATEGORY_LABEL[r.category] ?? r.category} | ${cell(r.statement)} | ${cell(r.impact)} | ${cell(r.mitigation)} | ${RISK_STATUS_LABEL[r.status as ThreatRiskStatus]} | ${cell(r.reason)} | ${r.sources.map((n) => `S${n}`).join('、')} |`),
    '',
    '---',
    '由獬豸审计生成；风险状态以獬豸中的研判为准。',
    '',
  ];
  return lines.join('\n');
}

export function renderThreatModelReport(store: Store, id: string): string {
  const d = threatModelDetail(store, id);
  if (!d) throw new AppError('THREAT_MODEL_NOT_FOUND', id);
  return threatModelMarkdown(d);
}
