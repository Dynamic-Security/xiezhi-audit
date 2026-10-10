// Markdown entry point: the renderer (react-markdown + GFM, MarkdownImpl.tsx) loads on first use so it stays
// out of the main bundle; until then the text is shown as it is.
import { Suspense, lazy } from 'react';
import { cx } from '../ui';
import M from './markdown.module.css';

const Impl = lazy(() => import('./MarkdownImpl'));

export function Markdown({ text, className }: { text: string; className?: string }) {
  return (
    <Suspense fallback={<div className={cx(M.md, M.plain, className)}>{text}</div>}>
      <Impl text={text} {...(className ? { className } : {})} />
    </Suspense>
  );
}
