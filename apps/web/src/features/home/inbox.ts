// “待我处理”: one list and one count for the home page and the sidebar badge. The same question
// asked by several audits of a project is shown once, with how many audits asked it.
import type { DashboardDto } from '@xiezhi/contracts';

type Inbox = DashboardDto['inbox'];
type Question = Inbox['questions'][number];

export interface QuestionGroup { latest: Question; count: number; blocking: boolean }

export function groupQuestions(questions: Question[]): QuestionGroup[] {
  const groups = new Map<string, QuestionGroup>();
  for (const q of questions) {
    const key = `${q.projectName}\u0000${q.text.trim()}`;
    const g = groups.get(key);
    if (!g) { groups.set(key, { latest: q, count: 1, blocking: q.blocking }); continue; }
    g.count++;
    g.blocking ||= q.blocking;
    if (q.createdAt > g.latest.createdAt) g.latest = q;
  }
  return [...groups.values()];
}

export function inboxCount(inbox: Inbox | undefined): number {
  if (!inbox) return 0;
  return groupQuestions(inbox.questions).length + inbox.awaitingConfirm.length + inbox.waitingBudget.length + inbox.interrupted.length
    + inbox.proposals.length + inbox.pendingVulns.length + (inbox.connectorWrites?.length ?? 0);
}
