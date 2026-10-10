// The built-in prompt catalog: one file per area; ids are unique across files.
import type { PromptDef } from '../registry.js';
import { CONVERSATION } from './conversation.js';
import { DATA_NOTES } from './data-notes.js';
import { DOMAINS } from './domains.js';
import { FACTS } from './facts.js';
import { HUNT } from './hunt.js';
import { REVIEW } from './review.js';
import { ROLE_RULES } from './role-rules.js';
import { SESSION } from './session.js';
import { SOLIDIFY } from './solidify.js';
import { STANDALONE } from './standalone.js';
import { UNDERSTANDING } from './understanding.js';
import { VERIFY } from './verify.js';

export const CATALOG: PromptDef[] = [
  ...ROLE_RULES, ...UNDERSTANDING, ...HUNT, ...DOMAINS, ...REVIEW, ...VERIFY, ...STANDALONE, ...CONVERSATION, ...SESSION, ...FACTS, ...SOLIDIFY, ...DATA_NOTES,
];
