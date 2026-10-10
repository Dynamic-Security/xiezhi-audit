import type { QueryClient } from '@tanstack/react-query';

/**
 * After a review changed a vulnerability: conversation revision cards about it may have expired, so the
 * conversation list (pending-card badges in the sidebar and workbench) and open conversations are fetched again.
 */
export async function refreshConversationCards(qc: QueryClient): Promise<void> {
  await Promise.all([qc.invalidateQueries({ queryKey: ['conversations'] }), qc.invalidateQueries({ queryKey: ['conversation'] }), qc.invalidateQueries({ queryKey: ['dashboard'] })]);
}
