// A sub-agent's part of a step in the trajectory tree: its start and end make the node's header, the rest of
// its events nest under it.
import type { EventDto } from '@xiezhi/contracts';

export interface SubNode { kind: 'sub'; id: string; started: EventDto | null; finished: EventDto | null; events: EventDto[] }

export function addSubEvent(n: SubNode, e: EventDto): void {
  if (e.type === 'task.started') n.started = e;
  else if (e.type === 'task.finished') n.finished = e;
  else {
    n.events.push(e);
    // A sub-agent that got no session slot never starts; the gave-up wait ends it.
    if (e.type === 'session.dequeued' && e.payload.gaveUp) n.finished = e;
  }
}

/** It ended without starting (no session slot within its wait). */
export const subNoSlot = (n: SubNode): boolean => n.finished?.type === 'session.dequeued';

/** Its goal: from task.started, or from the wait events of a sub-agent that never started. */
export function subGoal(n: SubNode): string {
  const g = n.started?.payload.goal ?? n.events.find((e) => typeof e.payload.goal === 'string')?.payload.goal;
  return typeof g === 'string' ? g : '';
}
