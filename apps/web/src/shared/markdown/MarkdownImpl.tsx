// Markdown for AI replies and skill previews. react-markdown + GFM without raw HTML:
// everything becomes React nodes. Model and skill text is data, so links show their full address
// and open only after a confirmation, images are never fetched, and code is highlighted from tokens.
import { useEffect, useState, type CSSProperties, type ReactNode } from 'react';
import ReactMarkdown, { type Components } from 'react-markdown';
import remarkGfm from 'remark-gfm';
import type { ThemedToken } from 'shiki/core';
import { ConfirmDialog, Icon, cx } from '../ui';
import { highlight } from './highlight';
import M from './markdown.module.css';

/** The part of a hast node the renderers read. */
interface HNode { type: string; tagName?: string; value?: string; properties?: Record<string, unknown>; children?: HNode[] }
const textOf = (n: HNode | undefined): string => (!n ? '' : n.type === 'text' ? n.value ?? '' : (n.children ?? []).map(textOf).join(''));

/** Fenced code: language, copy button, highlighting once the grammar has loaded (plain text until then). */
export function CodeBlock({ lang, code }: { lang: string; code: string }) {
  const [copied, setCopied] = useState(false);
  const [tokens, setTokens] = useState<ThemedToken[][] | null>(null);
  useEffect(() => {
    let live = true;
    setTokens(null);
    highlight(code, lang).then((t) => { if (live) setTokens(t); }, () => undefined);
    return () => { live = false; };
  }, [code, lang]);
  const copy = () => {
    void navigator.clipboard?.writeText(code).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }, () => undefined);
  };
  return (
    <div className={M.code}>
      <div className={M.codeHead}>
        <span>{lang || '代码'}</span>
        <button type="button" className={M.copy} onClick={copy} aria-label="复制代码">
          <Icon name={copied ? 'check' : 'copy'} size={12} />{copied ? '已复制' : '复制'}
        </button>
      </div>
      <pre className={cx(M.pre, tokens && M.hl)}>
        {tokens
          ? tokens.map((line, i) => (
            <span key={i} className={M.line}>
              {line.map((t, j) => <span key={j} style={t.htmlStyle as CSSProperties | undefined}>{t.content}</span>)}
              {'\n'}
            </span>
          ))
          : code}
      </pre>
    </div>
  );
}

/** Links are shown with their address; http(s) ones open in a new tab after a confirmation. */
function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  const [ask, setAsk] = useState(false);
  if (!/^https?:\/\//i.test(href)) return <span className={M.link} title={href}>{children}</span>;
  const plain = typeof children === 'string' ? children : Array.isArray(children) && children.every((c) => typeof c === 'string') ? children.join('') : null;
  return (
    <>
      <button type="button" className={M.link} title={href} onClick={() => setAsk(true)}>
        <span className={M.linkText}>{children}</span>{plain !== href && <span className={M.href}>（{href}）</span>}
      </button>
      <ConfirmDialog open={ask} onClose={() => setAsk(false)} title="打开外部链接" confirmText="打开"
        onConfirm={() => { setAsk(false); window.open(href, '_blank', 'noopener,noreferrer'); }}>
        <p>链接来自模型回复或知识内容，请确认地址可信：</p>
        <p className={M.confirmHref}>{href}</p>
      </ConfirmDialog>
    </>
  );
}

const components: Components = {
  pre: ({ node }) => {
    const code = (node as HNode | undefined)?.children?.find((c) => c.tagName === 'code');
    const cls = (code?.properties?.className as string[] | undefined) ?? [];
    const lang = cls.find((c) => c.startsWith('language-'))?.slice('language-'.length) ?? '';
    return <CodeBlock lang={lang} code={textOf(code).replace(/\n$/, '')} />;
  },
  a: ({ href, children }) => <ExternalLink href={href ?? ''}>{children}</ExternalLink>,
  img: ({ alt, src }) => <span className={M.img} title={typeof src === 'string' ? src : undefined}>[图片{alt ? `：${alt}` : ''}，未加载]</span>,
  table: ({ children }) => <div className={M.tableWrap}><table>{children}</table></div>,
};

export default function MarkdownImpl({ text, className }: { text: string; className?: string }) {
  return (
    <div className={cx(M.md, className)}>
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components} skipHtml>{text}</ReactMarkdown>
    </div>
  );
}
