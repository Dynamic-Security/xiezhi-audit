// Ajv validators compiled from TypeBox schemas (validate before write).
import { Ajv, type ErrorObject, type ValidateFunction } from 'ajv';
import type { TSchema, Static } from 'typebox';

const ajv = new Ajv({ strict: true, allErrors: true, allowUnionTypes: true });
const cache = new WeakMap<TSchema, ValidateFunction>();

export interface ValidationIssue { path: string; message: string }

function compile(schema: TSchema): ValidateFunction {
  let fn = cache.get(schema);
  if (!fn) {
    fn = ajv.compile(schema);
    cache.set(schema, fn);
  }
  return fn;
}

function toIssues(errors: ErrorObject[] | null | undefined): ValidationIssue[] {
  return (errors ?? []).map((e) => ({
    path: '$' + e.instancePath.replace(/\//g, '.'),
    message: e.message + (e.params && 'additionalProperty' in e.params ? `: ${String(e.params.additionalProperty)}` : '')
      + (e.params && 'allowedValues' in e.params ? `: ${JSON.stringify(e.params.allowedValues)}` : ''),
  }));
}

export function check<S extends TSchema>(schema: S, value: unknown): { ok: true; value: Static<S> } | { ok: false; issues: ValidationIssue[] } {
  const fn = compile(schema);
  if (fn(value)) return { ok: true, value: value as Static<S> };
  return { ok: false, issues: toIssues(fn.errors) };
}

export function assertValid<S extends TSchema>(schema: S, value: unknown, what: string): Static<S> {
  const r = check(schema, value);
  if (!r.ok) throw new Error(`${what} failed schema validation: ${r.issues.slice(0, 5).map((i) => `${i.path} ${i.message}`).join('; ')}`);
  return r.value;
}
