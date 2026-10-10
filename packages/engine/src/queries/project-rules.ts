// Project rules for the API: a project's rules, newest first, optionally of one vulnerability.
import type { Store } from '@xiezhi/store';
import type { ProjectRuleRow } from '../project-rules.js';

export function listProjectRules(store: Store, projectId: string, vulnId?: string): ProjectRuleRow[] {
  return vulnId
    ? store.all<ProjectRuleRow>('SELECT * FROM project_rule WHERE project_id = ? AND vulnerability_id = ? ORDER BY created_at DESC, id', projectId, vulnId)
    : store.all<ProjectRuleRow>('SELECT * FROM project_rule WHERE project_id = ? ORDER BY created_at DESC, id', projectId);
}
