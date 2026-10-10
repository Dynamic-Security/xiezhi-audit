// Reply parts in the order they happened: text, runs of tool calls and cards, split at the reply
// text length each call and card was recorded at. Pure, so it is unit-tested without a browser.
import type { CardDto, ToolCallDto } from '@xiezhi/contracts';

/** Card-producing tools are represented by their card. */
export const visibleTool = (c: ToolCallDto) => !c.name.startsWith('propose_') && c.name !== 'report_investigation' && c.name !== 'draft_connector';

export type AnyCard = Pick<CardDto, 'kind' | 'state' | 'data'> & { id: string; result?: CardDto['result']; targetRevision?: number | null; textOffset?: number | null };
export type Part = { kind: 'text'; text: string } | { kind: 'tools'; calls: ToolCallDto[] } | { kind: 'card'; card: AnyCard };

/**
 * Split the reply at the text length each tool call and card was recorded at. Older replies
 * have no offsets: their calls and cards come first, as they used to.
 */
export function replyParts(text: string, tools: ToolCallDto[], cards: AnyCard[]): Part[] {
  const items = [
    ...tools.filter(visibleTool).map((t) => ({ at: t.textOffset ?? 0, tool: t as ToolCallDto | undefined, card: undefined as AnyCard | undefined })),
    ...cards.map((c) => ({ at: c.textOffset ?? 0, tool: undefined as ToolCallDto | undefined, card: c as AnyCard | undefined })),
  ].sort((a, b) => a.at - b.at);
  const out: Part[] = [];
  let pos = 0;
  for (const it of items) {
    const at = Math.min(Math.max(it.at, pos), text.length);
    if (at > pos) { out.push({ kind: 'text', text: text.slice(pos, at) }); pos = at; }
    const last = out[out.length - 1];
    if (it.tool) { if (last?.kind === 'tools') last.calls.push(it.tool); else out.push({ kind: 'tools', calls: [it.tool] }); }
    if (it.card) out.push({ kind: 'card', card: it.card });
  }
  if (pos < text.length) out.push({ kind: 'text', text: text.slice(pos) });
  return out;
}

