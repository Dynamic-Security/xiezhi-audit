// Untrusted data boundaries and injection heuristics.
import { randomBytes } from 'node:crypto';
import { P } from '@xiezhi/knowledge';

export type UntrustedKind = 'repo_file' | 'tool_output' | 'connector' | 'user_upload' | 'knowledge';

/** Fixed note in front of unverified business / architecture knowledge; catalog `data.unverified_knowledge`. */
export const unverifiedKnowledgeNote = (): string => P('data.unverified_knowledge');

export function newNonce(): string {
  return randomBytes(12).toString('hex');
}

/** Wrap content in a nonce-tagged block; any boundary-looking text inside is escaped. */
/**
 * `verified` states whether the content is a verified fact (an authoritative connector result);
 * the block is a data boundary either way — never instructions.
 */
export function wrapUntrusted(nonce: string, kind: UntrustedKind, source: string, content: string, sha256?: string, verified = false): string {
  const escaped = content.replace(/<(\/?)untrusted_data/gi, '&lt;$1untrusted_data');
  const src = source.replace(/["<>\n]/g, '_');
  return `<untrusted_data nonce="${nonce}" kind="${kind}" source="${src}"${sha256 ? ` sha256="${sha256}"` : ''} verified="${verified}">\n${escaped}\n</untrusted_data nonce="${nonce}">`;
}

/** Catalog `boundary.declaration` (read-only: a security boundary). */
export function boundaryDeclaration(nonce: string): string {
  return P('boundary.declaration', { nonce });
}

export interface InjectionSignal { signal: string; line: number; excerpt: string }

const SIGNALS: [string, RegExp][] = [
  ['imperative_to_ai', /\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|above|all)\b.{0,20}\b(instructions?|rules?|prompts?)\b/i],
  ['imperative_to_ai', /(忽略|无视|忘记).{0,10}(之前|以上|所有|前面).{0,10}(指令|规则|提示|要求)/],
  ['imperative_to_ai', /\b(report|output|return)\b.{0,30}\b(zero|no)\b.{0,20}\b(findings?|issues?|vulnerabilit)/i],
  ['role_marker', /(^|\n)\s*(system|assistant)\s*:|<\|im_start\|>|<\|system\|>|\[INST\]/i],
  ['fake_tool_call', /"(tool_call|function_call|tool_use)"\s*:|\bsubmit_findings\s*\(/i],
  ['fake_boundary', /<\/?untrusted_data\b/i],
  ['unicode_tag', /[\u{E0000}-\u{E007F}]/u],
  ['bidi_control', /[‪-‮⁦-⁩]/],
];

export function detectInjection(text: string, maxSignals = 5): InjectionSignal[] {
  const out: InjectionSignal[] = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length && out.length < maxSignals; i++) {
    const line = lines[i]!;
    for (const [signal, re] of SIGNALS) {
      if (re.test(line)) {
        out.push({ signal, line: i + 1, excerpt: line.trim().slice(0, 160) });
        break;
      }
    }
  }
  return out;
}
