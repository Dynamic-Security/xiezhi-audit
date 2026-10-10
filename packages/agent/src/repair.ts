// Tool-call arguments that leaked the model's native parameter markup. Claude models served through an
// OpenAI-compatible gateway sometimes end one string field with `</field>` and write the next parameters as
// `<parameter name="x">value` inside it, so `x` is missing and the call is refused every time
// (seen with claude-haiku-5-5 over Chat Completions: `"focus": "…</focus>\n<parameter name=\"categories\">[\"sqli\"]"`).
// The same model also writes them as bare tags: `"threatModel": "…</threatModel>\n<affirm>…</affirm>\n<confirmation>pending</confirmation>"`.

const OPEN = /<\/[A-Za-z_][\w-]*>\s*<parameter name="([A-Za-z_][\w-]*)">/;
const NEXT = /(?:<\/parameter>)?\s*<parameter name="([A-Za-z_][\w-]*)">/g;
const TAG = /^\s*<([A-Za-z_][\w-]*)>/;
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function parseValue(text: string): unknown {
  const t = text.replace(/\s*<\/parameter>\s*$/, '').trim();
  try { return JSON.parse(t); } catch { return t; }
}

/**
 * Bare-tag leak in field `key`: the string closes its own field (`</key>`) and goes on with `<name>value</name>`
 * siblings, the last one possibly unclosed. Only the field's own closing tag starts it, so XML quoted in a
 * field (a MyBatis mapper as evidence) stays text. Null when the string does not leak this way.
 */
function bareTagLeak(key: string, v: string): { head: string; fields: [string, string][] } | null {
  const close = new RegExp(`</${escape(key)}>\\s*(?=<[A-Za-z_][\\w-]*>)`).exec(v);
  if (!close) return null;
  const fields: [string, string][] = [];
  let rest = v.slice(close.index + close[0].length);
  for (let m = TAG.exec(rest); m; m = TAG.exec(rest)) {
    const name = m[1]!;
    rest = rest.slice(m[0].length);
    const end = rest.indexOf(`</${name}>`);
    fields.push([name, end < 0 ? rest : rest.slice(0, end)]);
    if (end < 0) break;
    rest = rest.slice(end + name.length + 3);
  }
  return fields.length ? { head: v.slice(0, close.index).trimEnd(), fields } : null;
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
      const bare = bareTagLeak(k, v);
      if (!bare) { out[k] = v; continue; }
      out[k] = bare.head;
      for (const [name, text] of bare.fields) if (!(name in src) && !(name in out)) out[name] = parseValue(text);
      changed = true;
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
