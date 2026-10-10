// `<prefix>_<ULID>` identifiers: time-ordered, readable, debuggable.
import { randomBytes } from 'node:crypto';

const ENC = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
let lastTime = -1;
let lastRandom: number[] = [];

function encodeTime(ms: number): string {
  let out = '';
  for (let i = 9; i >= 0; i--) {
    out = ENC[ms % 32]! + out;
    ms = Math.floor(ms / 32);
  }
  return out;
}

/** Monotonic ULID: within the same millisecond the random part is incremented. */
export function ulid(now = Date.now()): string {
  if (now === lastTime) {
    let i = lastRandom.length - 1;
    while (i >= 0 && lastRandom[i] === 31) { lastRandom[i] = 0; i--; }
    if (i >= 0) lastRandom[i]! += 1;
  } else {
    const bytes = randomBytes(16);
    lastRandom = Array.from({ length: 16 }, (_, i) => bytes[i]! % 32);
    lastTime = now;
  }
  return encodeTime(now) + lastRandom.map((n) => ENC[n]).join('');
}

export const ID_PREFIXES = {
  project: 'prj', repository: 'rep', snapshot: 'snp', audit: 'aud', step: 'stp', question: 'qst',
  finding: 'fnd', vulnerability: 'vul', occurrence: 'occ', evidence: 'evd', revision: 'rev',
  coverage: 'cov', budgetAdjustment: 'bud', skillUsage: 'sku', export: 'exp', request: 'req',
  analysis: 'anl', repoAnalysis: 'ran', topologyNode: 'tpn', topologyEdge: 'tpe', huntBasis: 'hbs', riskHunt: 'hnt', huntTarget: 'htg',
  knowledgeDraft: 'kdr', connector: 'con', connectorBinding: 'cbd', syncRecord: 'syn', connectorCall: 'ccl', connectorWrite: 'cwr', architectureImport: 'aim', push: 'psh',
  conversation: 'cnv', message: 'msg', card: 'crd', workItem: 'wki', session: 'ses', hypothesis: 'hyp',
  threatModel: 'thm', threatSource: 'tms', threatRisk: 'thr', obligation: 'obl', fact: 'fct', factRef: 'fcr', egress: 'egr', projectRule: 'prl', verificationCase: 'vcs', fixSuggestion: 'fix',
} as const;

export function newId(kind: keyof typeof ID_PREFIXES): string {
  return `${ID_PREFIXES[kind]}_${ulid()}`;
}
