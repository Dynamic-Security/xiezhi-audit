// Product mark: a horn piercing a ring — the 獬豸 “points at what is crooked”. The tile is
// ink in both themes; the hairline border keeps its edge visible on a dark sidebar. Sources: docs/brand/.
export function BrandMark({ size }: { size: number }) {
  const px = 140 / size; // one screen pixel in viewBox units
  return (
    <svg width={size} height={size} viewBox="0 0 140 140" aria-hidden="true" focusable="false"
      style={{ display: 'block', flex: 'none' }}>
      <rect width="140" height="140" rx="32" fill="#1F1C19" />
      <rect x={px / 2} y={px / 2} width={140 - px} height={140 - px} rx={32 - px / 2} fill="none" strokeWidth={px} style={{ stroke: 'var(--border)' }} />
      <path d="M99.4 63 A34 34 0 1 1 81.6 48" fill="none" stroke="#F2EDE4" strokeWidth={size < 32 ? 9 : 7} strokeLinecap="round" />
      <path d="M59 106 C57 75 76 48 118 27 C95 47 83 72 77 106 Q68 112 59 106 Z" fill="#D9973A" />
    </svg>
  );
}
