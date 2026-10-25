// The “让 Agent 自行查询” chip sends the answer the engine recognises and never saves as a fact.
import { describe, expect, it } from 'vitest';
import { DEFER_TO_AGENT_ANSWER as engineText } from '@xiezhi/contracts';
import { DEFER_TO_AGENT_ANSWER } from '../src/features/audits/questionAnswers';

describe('question answers', () => {
  it('the defer chip sends the contracts text', () => {
    expect(DEFER_TO_AGENT_ANSWER).toBe(engineText);
  });
});
