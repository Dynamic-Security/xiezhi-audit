// conversation UI logic: reply parts in the order they happened, and Markdown rendered as
// data — no raw HTML, only http(s) links become (confirmed) buttons, images are never fetched.
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import type { ToolCallDto } from '@xiezhi/contracts';
import { replyParts, type AnyCard } from '../src/features/conversations/parts';
import MarkdownImpl from '../src/shared/markdown/MarkdownImpl';

const tool = (callId: string, textOffset: number | null, name = 'read'): ToolCallDto =>
  ({ callId, name, argsSummary: '{}', phase: 'finished', ok: true, resultPreview: null, textOffset });
const card = (id: string, textOffset: number | null): AnyCard => ({ id, kind: 'investigation', state: 'info', data: {}, textOffset });

describe('reply parts', () => {
  it('interleaves text, tool calls and cards at their recorded offsets', () => {
    const parts = replyParts('先读代码。发现问题。结论。', [tool('a', 5), tool('b', 5), tool('p', 5, 'propose_revision')], [card('c1', 10)]);
    expect(parts.map((p) => p.kind)).toEqual(['text', 'tools', 'text', 'card', 'text']);
    expect(parts[0]).toEqual({ kind: 'text', text: '先读代码。' });
    expect(parts[1]).toMatchObject({ kind: 'tools', calls: [{ callId: 'a' }, { callId: 'b' }] }); // propose_* shows as its card
    expect(parts[4]).toEqual({ kind: 'text', text: '结论。' });
  });
  it('replies recorded before offsets existed keep calls and cards first', () => {
    expect(replyParts('正文', [tool('a', null)], [card('c', null)]).map((p) => p.kind)).toEqual(['tools', 'card', 'text']);
  });
  it('offsets beyond the text (a card added after the reply) go last', () => {
    expect(replyParts('正文', [], [card('c', 99)]).map((p) => p.kind)).toEqual(['text', 'card']);
  });
});

describe('markdown as data', () => {
  const html = (text: string) => renderToStaticMarkup(createElement(MarkdownImpl, { text }));
  it('renders GFM tables and fenced code with its language', () => {
    const out = html('| a | b |\n| --- | --- |\n| 1 | 2 |\n\n```java\nint x = 1;\n```');
    expect(out).toContain('<table>');
    expect(out).toContain('<td>1</td>');
    expect(out).toContain('java');
    expect(out).toContain('int x = 1;');
  });
  it('drops raw HTML and never produces anchors, scripts or images', () => {
    const out = html('<script>alert(1)</script><img src=x onerror=alert(1)>\n\n[点我](javascript:alert(1)) [官网](https://example.com) ![图](https://tracker.example/p.png)');
    expect(out).not.toMatch(/<script|<img|<a |onerror|javascript:/i);
    expect(out).toContain('https://example.com'); // the address is shown next to the link text
    expect(out).toContain('[图片：图，未加载]');
  });
});
