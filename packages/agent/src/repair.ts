// Tool-call arguments that leaked the model's native parameter markup. Claude models served through an
// OpenAI-compatible gateway sometimes end one string field with `</field>` and write the next parameters as
// `<parameter name="x">value` inside it, so `x` is missing and the call is refused every time
// (seen with claude-haiku-5-5 over Chat Completions: `"focus": "…</focus>\n<parameter name=\"categories\">[\"sqli\"]"`).
// The same model also writes them as bare tags: `"threatModel": "…</threatModel>\n<affirm>…</affirm>\n<confirmation>pending</confirmation>"`.

const OPEN = /<\/[A-Za-z_][\w-]*>\s*<parameter name="([A-Za-z_][\w-]*)">/;
const NEXT = /(?:<\/parameter>)?\s*<parameter name="([A-Za-z_][\w-]*)">/g;

function parseValue(text: string): unknown {
  const t = text.replace(/\s*<\/parameter>\s*$/, '').trim();
  try { return JSON.parse(t); } catch { return t; }
}

/**
 * The other leaked form (claude-haiku-5-5 in submit_challenge): the field closes with its own tag and the
 * next fields follow as plain elements — `"affirm": "…</affirm>\n<confirmation>maintain</confirmation>\n<confidenceDelta>-0.2</confidenceDelta>"`.
 * Split only when the field's own closing tag is followed by nothing but such elements (the last may be unclosed) for
 * fields the call does not have, so XML or HTML quoted in a finding is left alone.
 */
function splitElements(key: string, v: string, src: Record<string, unknown>, out: Record<string, unknown>): boolean {
  const close = `</${key}>`;
  const at = v.indexOf(close);
  if (at < 0) return false;
  const tail = v.slice(at + close.length);
  const element = /\s*<([A-Za-z_][\w-]*)>([\s\S]*?)(?:<\/\1>|$)/y;
  const found: [string, unknown][] = [];
  let pos = 0;
  for (let e = element.exec(tail); e && e[0].length; e = element.exec(tail)) {
    found.push([e[1]!, parseValue(e[2]!)]);
    pos = element.lastIndex;
  }
  if (!found.length || tail.slice(pos).trim() || found.some(([n]) => n in src || n === key)) return false;
  out[key] = v.slice(0, at).trimEnd();
  for (const [n, value] of found) if (!(n in out)) out[n] = value;
  return true;
}

/** Splits leaked parameters out of string fields (at any depth); returns the input itself when nothing leaked. */
export function repairLeakedParameters(value: unknown): unknown {
  // a split-out value can leak the next fields in turn (`"affirm": "…</affirm>\n<confirmation>…"`).
  let out = repairOnce(value);
  for (let i = 0; i < 5; i++) {
    const next = repairOnce(out);
    if (next === out) break;
    out = next;
  }
  return out;
}

function repairOnce(value: unknown): unknown {
  if (Array.isArray(value)) {
    let changed = false;
    const out = value.map((v) => { const r = repairOnce(v); if (r !== v) changed = true; return r; });
    return changed ? out : value;
  }
  if (!value || typeof value !== 'object') return value;
  const src = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  let changed = false;
  for (const [k, v] of Object.entries(src)) {
    if (typeof v !== 'string') {
      const r = repairOnce(v);
      if (r !== v) changed = true;
      out[k] = r;
      continue;
    }
    const m = OPEN.exec(v);
    if (!m) {
      if (splitElements(k, v, src, out)) changed = true;
      else out[k] = v;
      continue;
    }
    out[k] = v.slice(0, m.index).trimEnd();
    const rest = v.slice(m.index + m[0].length);
    // Each `<parameter name=…>` starts the next field; its value runs to the next one or the end of the string.
    const names = [m[1]!];
    const values: string[] = [];
    let last = 0;
    NEXT.lastIndex = 0;
    for (let n = NEXT.exec(rest); n; n = NEXT.exec(rest)) {
      values.push(rest.slice(last, n.index));
      names.push(n[1]!);
      last = n.index + n[0].length;
    }
    values.push(rest.slice(last));
    names.forEach((name, i) => { if (!(name in src) && !(name in out)) out[name] = parseValue(values[i]!); });
    changed = true;
  }
  return changed ? out : value;
}

/**
 * Top-level fields sent as JSON text instead of the array / object itself (`"findings": "[{…}]"`, seen with
 * claude-haiku-5-5), decoded. The caller keeps a decoded field only when the schema check improves.
 */
export function decodedJsonFields(value: unknown): [string, unknown][] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [];
  const out: [string, unknown][] = [];
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v !== 'string' || !/^\s*[[{]/.test(v)) continue;
    try {
      const d = JSON.parse(v) as unknown;
      if (d && typeof d === 'object') out.push([k, d]);
    } catch { /* not JSON */ }
  }
  return out;
}

/** The arguments with every required top-level array the call left out set to `[]`; the input itself when none is missing. */
export function withEmptyRequiredLists(schema: { required?: string[]; properties?: Record<string, { type?: string }> }, value: unknown): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value;
  const v = value as Record<string, unknown>;
  const missing = (schema.required ?? []).filter((k) => !(k in v) && schema.properties?.[k]?.type === 'array');
  return missing.length ? { ...v, ...Object.fromEntries(missing.map((k) => [k, []])) } : value;
}
