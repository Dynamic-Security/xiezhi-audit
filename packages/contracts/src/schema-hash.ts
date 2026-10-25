// Hash of the submit contracts the agent is given (replay fixture header: tool-schema hash). A replay
// fixture recorded against other schemas is stale and must be re-recorded.
import { canonicalJson, sha256Hex } from './hash.js';
import {
  SubmitChallenge, SubmitDecision, SubmitFindings, SubmitPlan, SubmitReverify, SubmitStateUpdate, SubmitVerdictReview,
} from './submit.js';
import { SubmitRiskVerdicts } from './hunt.js';
import { DraftConnector, ProposeAuditPlan, ProposeHunt, ProposeMerge, ProposeReverify, ProposeRevision, ProposeSplit, ReportInvestigation } from './conversation.js';

export function toolSchemaHash(): string {
  return sha256Hex(canonicalJson({
    SubmitChallenge, SubmitDecision, SubmitFindings, SubmitPlan, SubmitReverify, SubmitStateUpdate, SubmitVerdictReview, SubmitRiskVerdicts,
    DraftConnector, ProposeAuditPlan, ProposeHunt, ProposeMerge, ProposeReverify, ProposeRevision, ProposeSplit, ReportInvestigation,
  }));
}
