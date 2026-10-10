// System prompt composition — fixed order:
// 1 role + data boundary, 2 scene, 3 mandatory knowledge (hard exclusions etc.), 4 threat model,
// 5 cognitive-state slice, 6 skill index.
import type { Scene, StepKind } from '@xiezhi/contracts';
import { canonicalJson, sha256Hex } from '@xiezhi/contracts';
import { P } from '@xiezhi/knowledge';
import { boundaryDeclaration } from './boundary.js';

// the texts are catalog entries in the knowledge base (`role.*`, `scene.*`, `rules.*`,
// `conversation.*`); an audit's or conversation's frozen overrides apply through the prompt scope.
const ROLE_STEPS: StepKind[] = ['plan', 'profile', 'triage', 'hunt', 'challenge', 'reconcile', 'verify-fix', 'report'];
const roleId = (k: StepKind) => `role.${k.replace(/-/g, '_')}`;
const roles = (): Partial<Record<StepKind, string>> => Object.fromEntries(ROLE_STEPS.map((k) => [k, P(roleId(k))]));
const role = (k: StepKind) => P(roleId(ROLE_STEPS.includes(k) ? k : 'hunt'));
const SCENE_KEYS: Scene[] = ['full', 'incremental', 'risk_hunt', 'reverify'];
const scenes = (): Record<Scene, string> => Object.fromEntries(SCENE_KEYS.map((k) => [k, P(`scene.${k}`)])) as Record<Scene, string>;
const pendingRule = () => P('rules.pending');
const rules = () => P('rules.audit', { pendingRule: pendingRule() });

export interface PromptParts {
  step: StepKind;
  scene: Scene;
  nonce: string;
  sceneDetail?: string;
  mandatoryKnowledge: { name: string; text: string }[];
  threatModel?: string;
  cognitiveSlice?: string;
  /** Absent for sessions without `load_skill` (submit-only judgements): no index to point at. */
  skillIndex?: string;
  extra?: string;
}

/** Named sections of a step's system prompt, in prompt order (their sizes are recorded per session). */
export type PromptSection = 'role' | 'scene' | 'knowledge' | 'threat_model' | 'cognitive' | 'skill_index' | 'extra' | 'boundary';

export function systemPromptSections(p: PromptParts): { name: PromptSection; text: string }[] {
  const parts: { name: PromptSection; text: string }[] = [];
  // the data-boundary declaration carries the session's nonce, so it goes last — the sections before
  // it are the same for sessions of the same kind and can be served from the provider's prompt cache.
  parts.push({ name: 'role', text: `# 角色\n${role(p.step)}` });
  parts.push({ name: 'scene', text: `# 场景\n${P(`scene.${p.scene}`)}${p.sceneDetail ? `\n${p.sceneDetail}` : ''}\n\n${rules()}` });
  if (p.mandatoryKnowledge.length) {
    parts.push({ name: 'knowledge', text: `# 必读知识\n${p.mandatoryKnowledge.map((k) => `## [${k.name}]\n${k.text.replace(/^---[\s\S]*?---\n/, '')}`).join('\n\n')}` });
  }
  if (p.threatModel) parts.push({ name: 'threat_model', text: `# 威胁模型摘要\n${p.threatModel}` });
  if (p.cognitiveSlice) parts.push({ name: 'cognitive', text: `# 当前认知状态（由系统维护）\n${p.cognitiveSlice}` });
  if (p.skillIndex !== undefined) parts.push({ name: 'skill_index', text: `# 知识索引\n${P('section.skill_index')}\n${p.skillIndex}` });
  if (p.extra) parts.push({ name: 'extra', text: p.extra });
  parts.push({ name: 'boundary', text: boundaryDeclaration(p.nonce) });
  return parts;
}

export function buildSystemPrompt(p: PromptParts): string {
  return systemPromptSections(p).map((s) => s.text).join('\n\n');
}

// ---- conversations ----------------------------------------------------------------------

export interface ConversationPromptParts {
  nonce: string;
  /** Mentioned objects rendered as data blocks (vulnerability details, audit summaries …). */
  context: string;
  /** What code the read tools can see (frozen snapshots), or why none. */
  codeScope: string;
  mandatoryKnowledge: { name: string; text: string }[];
  skillIndex: string;
  /** Connector usage section when connectors are available. */
  connectors?: string;
}

const conversationRules = () => P('conversation.rules', { pendingRule: pendingRule() });

export function buildConversationPrompt(p: ConversationPromptParts): string {
  const parts: string[] = [];
  parts.push(`# 角色\n${P('conversation.role')}\n\n${boundaryDeclaration(p.nonce)}`);
  parts.push(conversationRules());
  parts.push(`# 可读取的代码\n${p.codeScope}`);
  if (p.context) parts.push(`# 本对话引用的对象（数据）\n${p.context}`);
  if (p.mandatoryKnowledge.length) {
    parts.push(`# 必读知识\n${p.mandatoryKnowledge.map((k) => `## [${k.name}]\n${k.text.replace(/^---[\s\S]*?---\n/, '')}`).join('\n\n')}`);
  }
  if (p.connectors) parts.push(p.connectors);
  parts.push(`# 知识索引\n${P('section.skill_index')}\n${p.skillIndex}`);
  return parts.join('\n\n');
}


/**
 * Hash of the fixed prompt templates (part of the replay fixture header): a replay fixture recorded under other
 * templates is stale. Step-specific instructions written by the engine are covered by the replay mismatch.
 * computed over the texts in effect (the defaults give the same hash as before the catalog).
 */
export function promptTemplateHash(): string {
  return sha256Hex(canonicalJson({ roles: roles(), scenes: scenes(), rules: rules(), conversation: conversationRules() }));
}
