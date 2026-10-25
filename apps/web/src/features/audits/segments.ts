// Status-bar items over the engine's execution segments (ExecutionDto.segments).

/**
 * Segments shown as one: 画像 and 威胁建模 are one item, like the step list's “画像与威胁建模” (both are the
 * system-understanding stage; they run as two sessions). Without a profile (incremental audits: 影响范围 then 威胁建模) the threat model stays its own item.
 */
const MERGED: Partial<Record<string, string[]>> = { profile: ['profile', 'threat'] };
/** The status bar's items in order, each with the engine segments it covers. */
export function segmentItems(segments: readonly string[]): { key: string; members: string[] }[] {
  const absorbed = new Set(Object.entries(MERGED).filter(([k]) => segments.includes(k)).flatMap(([k, m]) => m!.filter((x) => x !== k)));
  return segments.filter((k) => !absorbed.has(k)).map((k) => ({ key: k, members: (MERGED[k] ?? [k]).filter((m) => segments.includes(m)) }));
}
/** The engine segments a selected status-bar item stands for (filtering the trajectory). */
export function segmentMembers(selected: string, segments: readonly string[]): string[] {
  return segmentItems(segments).find((i) => i.key === selected)?.members ?? [selected];
}
