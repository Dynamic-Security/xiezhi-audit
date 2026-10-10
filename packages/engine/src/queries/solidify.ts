// Verification cases and fix suggestions of a vulnerability for the API, newest first.
import type { Store } from '@xiezhi/store';
import type { FixSuggestionRow } from '../fixes.js';
import type { VerificationCaseRow } from '../verification.js';

export function listVerificationCases(store: Store, vulnId: string): VerificationCaseRow[] {
  return store.all<VerificationCaseRow>('SELECT * FROM verification_case WHERE vulnerability_id = ? ORDER BY created_at DESC, id', vulnId);
}

export function listFixSuggestions(store: Store, vulnId: string): FixSuggestionRow[] {
  return store.all<FixSuggestionRow>('SELECT * FROM fix_suggestion WHERE vulnerability_id = ? ORDER BY created_at DESC, id', vulnId);
}
