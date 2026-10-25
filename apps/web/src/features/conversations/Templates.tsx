// Quick-start templates of an empty conversation: grouped prompts that fill the composer.
// 【…】 marks what the user fills in (Tab jumps to the next one); the AI asks for anything still missing and
// answers with a card, so a template never starts anything by itself.
import { useState } from 'react';
import type { MentionDto } from '@xiezhi/contracts';
import { Icon, cx, ui, type IconName } from '../../shared/ui';
import C from './conversations.module.css';

export interface Template { title: string; text: string }
export interface TemplateGroup { key: string; label: string; icon: IconName; items: Template[] }

export const TEMPLATE_GROUPS: TemplateGroup[] = [
  {
    key: 'project', label: '创建项目', icon: 'folder', items: [
      { title: '新建项目并全量审计', text: '新建项目【项目名】，添加仓库【Git 地址或本机目录】，建好后直接做一次全量审计' },
      { title: '新建多仓库项目', text: '新建项目【项目名】，添加这些仓库：\n- 【仓库 1 的 Git 地址或本机目录】\n- 【仓库 2 的 Git 地址或本机目录】\n添加后分析各仓库的角色与调用关系' },
      { title: '分析项目结构', text: '分析 @【项目】 各仓库的角色与调用关系' },
    ],
  },
  {
    key: 'threat', label: '威胁建模', icon: 'shield', items: [
      { title: '基于需求文档建模', text: '为 @【项目】 做需求威胁建模，需求如下：\n【粘贴需求文档或功能描述】' },
      { title: '基于在线文档建模', text: '用连接器读取在线需求文档【文档链接】，为 @【项目】 做威胁建模' },
      { title: '查看未处理的风险', text: '@【项目】 的威胁建模里还有哪些高风险项没有处理？' },
    ],
  },
  {
    key: 'audit', label: '代码审计', icon: 'play', items: [
      { title: '全量审计', text: '对 @【项目】 做一次全量审计' },
      { title: '增量审计', text: '对 @【项目】 做增量审计，对比【基线分支、提交或上次审计】' },
      { title: '专项审计', text: '对 @【项目】 做专项审计，只关注【越权 / 注入 / SSRF / 业务逻辑】，预算【2M】 tokens' },
    ],
  },
  {
    key: 'hunt', label: '复验与排查', icon: 'target', items: [
      { title: '复验已修复的漏洞', text: '复验 @【项目】 所有标为已修复的漏洞' },
      { title: '排查 CVE 影响', text: '排查所有项目是否受【CVE 编号】影响' },
      { title: '按知识排查', text: '用知识 @【知识】 排查【全部项目或指定项目】' },
    ],
  },
  {
    key: 'vuln', label: '漏洞跟进', icon: 'bug', items: [
      { title: '利用条件', text: '@【漏洞】 在什么条件下可以被利用？' },
      { title: '修复建议与验证用例', text: '为 @【漏洞】 生成修复建议和验证用例' },
      { title: '防复发规则', text: '为 @【漏洞】 生成项目规则，防止同类问题再出现' },
    ],
  },
  {
    key: 'connector', label: '连接器', icon: 'link', items: [
      { title: '同步漏洞到工单', text: '配置【飞书多维表格 / Jira / 内部工单】连接器，用来同步漏洞' },
      { title: '读取上下文', text: '配置一个读取【CMDB / 网关配置 / 文档系统】的连接器' },
    ],
  },
];

/** The next 【…】 at or after `from` (wrapping to the start), as [start, end]. */
export function nextPlaceholder(text: string, from = 0): [number, number] | null {
  const re = /【[^【】\n]*】/g;
  const all = [...text.matchAll(re)].map((m) => [m.index!, m.index! + m[0].length] as [number, number]);
  return all.find(([s]) => s >= from) ?? all[0] ?? null;
}

/** The page object stands in for its placeholder: it is sent as the message's reference anyway. */
export function fillContext(text: string, context?: MentionDto | null): string {
  // The spaces around an @-mention are not needed around plain words.
  if (context?.kind === 'project') return text.replace(/ ?@【项目】 ?/g, '当前项目');
  if (context?.kind === 'vuln') return text.replace(/ ?@【漏洞】 ?/g, '这个漏洞');
  return text;
}

export function QuickStart({ context, onPick }: { context?: MentionDto | null; onPick: (text: string) => void }) {
  // The page object may arrive after the first render: follow it until the user picks a group.
  const [picked, setGroup] = useState<string | null>(null);
  const group = picked ?? (context?.kind === 'vuln' ? 'vuln' : context?.kind === 'project' ? 'audit' : 'project');
  const g = TEMPLATE_GROUPS.find((x) => x.key === group) ?? TEMPLATE_GROUPS[0]!;
  return (
    <div className={C.templates}>
      <div className={C.templateTabs} role="tablist" aria-label="快速开始">
        {TEMPLATE_GROUPS.map((x) => (
          <button key={x.key} role="tab" aria-selected={x.key === g.key} className={cx(ui.chip, x.key === g.key && ui.chipOn)} onClick={() => setGroup(x.key)}>
            <Icon name={x.icon} size={12} />{x.label}
          </button>
        ))}
      </div>
      <div className={C.templateList} role="tabpanel">
        {g.items.map((t) => {
          const text = fillContext(t.text, context);
          return (
            <button key={t.title} className={C.template} onClick={() => onPick(text)}>
              <b>{t.title}</b>
              <span className={C.templateText}>{text}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
