// TanStack Query hooks. Keys follow the resource hierarchy.
import { useMutation, useQuery, useQueryClient, type UseQueryOptions } from '@tanstack/react-query';
import type {
  AnalysisDto, ConnectorDto, GitCredentialDto, AuditDetailDto, AuditSummaryDto, CoverageDto, CoverageItemDto, DashboardDto, DiagnosticsDto, ExportDto, FindingDto,
  GeneralSettingsDto, HuntDto, ModelSettingsDto, Page, PlanDto, ProjectDto, ProviderDto, QuestionDto, RefDto, RepoDto, RepoProbeDto,
  ProjectConnectorDto, PushGuideDto, SyncRecordDto, ConversationDto, MessagePageDto, MentionCandidateDto, ReviewStatsDto, RevisionDto, SkillDto, SourceDto, StepDto, TreeEntryDto, UsageRow, VulnDetailDto, VulnSummaryDto,
  ExecutionDto, AiReportDefaultsDto, ExportPreviewDto } from '@xiezhi/contracts';
import { api } from './client';
import type { TrajectoryFilter, TrajectoryPage } from '../stream/cache';

export const qk = {
  dashboard: ['dashboard'] as const,
  projects: ['projects'] as const,
  project: (pid: string) => ['project', pid] as const,
  repos: (pid: string) => ['project', pid, 'repos'] as const,
  analysis: (pid: string) => ['project', pid, 'analysis'] as const,
  audits: (filters: Record<string, string | undefined>) => ['audits', filters] as const,
  audit: (aid: string) => ['audit', aid] as const,
  plan: (aid: string) => ['audit', aid, 'plan'] as const,
  /** The filter object is read back by the event stream to append live events (stream/cache.ts). */
  trajectory: (aid: string, filter: TrajectoryFilter) => ['audit', aid, 'trajectory', filter] as const,
  steps: (aid: string) => ['audit', aid, 'steps'] as const,
  execution: (aid: string) => ['audit', aid, 'execution'] as const,
  questions: (aid: string) => ['audit', aid, 'questions'] as const,
  findings: (aid: string) => ['audit', aid, 'findings'] as const,
  coverage: (aid: string) => ['audit', aid, 'coverage'] as const,
  coverageItems: (aid: string, kind: string) => ['audit', aid, 'coverage', 'items', kind] as const,
  usage: (aid: string, by: string) => ['audit', aid, 'usage', by] as const,
  exports: (aid: string) => ['audit', aid, 'exports'] as const,
  vulns: (pid: string, filters: string) => ['vulns', pid, filters] as const,
  vuln: (vid: string) => ['vuln', vid] as const,
  revisions: (vid: string) => ['vuln', vid, 'revisions'] as const,
  links: (vid: string) => ['vuln', vid, 'links'] as const,
  source: (aid: string, rid: string, path: string, from: number, to: number) => ['source', aid, rid, path, from, to] as const,
  tree: (aid: string, rid: string, path: string) => ['tree', aid, rid, path] as const,
  providers: ['settings', 'providers'] as const,
  gitCredentials: ['settings', 'git-credentials'] as const,
  models: ['settings', 'models'] as const,
  scene: (s: string) => ['settings', 'scene', s] as const,
  general: ['settings', 'general'] as const,
  diagnostics: ['diagnostics'] as const,
  knowledge: (pid?: string) => ['knowledge', pid ?? 'global'] as const,
  refs: (rid: string, kind: string, q: string) => ['refs', rid, kind, q] as const,
  conversations: (status: string) => ['conversations', status] as const,
  conversation: (cid: string) => ['conversation', cid] as const,
  messages: (cid: string) => ['conversation', cid, 'messages'] as const,
};

type Opts<T> = Omit<UseQueryOptions<T>, 'queryKey' | 'queryFn'>;
export const qs = (o: Record<string, string | string[] | undefined>) => {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(o)) for (const x of Array.isArray(v) ? v : v ? [v] : []) p.append(k, x);
  const s = p.toString();
  return s ? `?${s}` : '';
};

export const useDashboard = () => useQuery({ queryKey: qk.dashboard, queryFn: () => api.get<DashboardDto>('/dashboard'), refetchInterval: 30_000 });
export const useProjects = () => useQuery({ queryKey: qk.projects, queryFn: () => api.get<ProjectDto[]>('/projects') });
export const useProject = (pid: string) => useQuery({ queryKey: qk.project(pid), queryFn: () => api.get<ProjectDto>(`/projects/${pid}`) });
/** Latest repository analysis; polls while it runs. */
export const useAnalysis = (pid: string) =>
  useQuery({
    queryKey: qk.analysis(pid), queryFn: () => api.get<{ analysis: AnalysisDto | null }>(`/projects/${pid}/analysis`),
    refetchInterval: (q) => (q.state.data?.analysis?.status === 'running' ? 1500 : false), refetchIntervalInBackground: true,
  });
export const useRepos = (pid: string) => useQuery({ queryKey: qk.repos(pid), queryFn: () => api.get<RepoDto[]>(`/projects/${pid}/repos`) });
export const useAudits = (filters: Record<string, string | undefined>, opts?: Opts<Page<AuditSummaryDto>>) =>
  useQuery({ queryKey: qk.audits(filters), queryFn: () => api.get<Page<AuditSummaryDto>>(`/audits${qs({ ...filters, limit: '200' })}`), ...opts });
export const useAudit = (aid: string, opts?: Opts<AuditDetailDto>) => useQuery({ queryKey: qk.audit(aid), queryFn: () => api.get<AuditDetailDto>(`/audits/${aid}`), ...opts });
export const usePlan = (aid: string, enabled = true) => useQuery({ queryKey: qk.plan(aid), queryFn: () => api.get<PlanDto>(`/audit-plans/${aid}`), enabled });
export const useQuestions = (aid: string) => useQuery({ queryKey: qk.questions(aid), queryFn: () => api.get<QuestionDto[]>(`/audits/${aid}/questions`) });
export const useFindings = (aid: string) => useQuery({ queryKey: qk.findings(aid), queryFn: () => api.get<FindingDto[]>(`/audits/${aid}/findings`) });
export const useCoverage = (aid: string, live = false) => useQuery({ queryKey: qk.coverage(aid), queryFn: () => api.get<CoverageDto>(`/audits/${aid}/coverage`), ...(live ? { refetchInterval: 5000 } : {}) });
export const useCoverageItems = (aid: string, kind: string) =>
  useQuery({ queryKey: qk.coverageItems(aid, kind), queryFn: () => api.get<CoverageItemDto[]>(`/audits/${aid}/coverage/items${qs({ kind })}`) });
export const useUsage = (aid: string, by: string) => useQuery({ queryKey: qk.usage(aid, by), queryFn: () => api.get<UsageRow[]>(`/audits/${aid}/usage?groupBy=${by}`) });
export const useExports = (aid: string) => useQuery({ queryKey: qk.exports(aid), queryFn: () => api.get<ExportDto[]>(`/audits/${aid}/exports`) });
/** AI report defaults of an audit: report model, source, fallback, token estimate for these options. */
export const useAiReportDefaults = (aid: string, o: { snippets: boolean; includePending: boolean }, enabled: boolean) =>
  useQuery({
    queryKey: ['audit', aid, 'ai-report', o.snippets, o.includePending] as const, enabled,
    queryFn: () => api.get<AiReportDefaultsDto>(`/audits/${aid}/ai-report?snippets=${o.snippets ? 1 : 0}&includePending=${o.includePending ? 1 : 0}`),
  });
/** One export, polled every 1.5 s while an AI report is being written. */
export const useExport = (eid: string | null) =>
  useQuery({
    queryKey: ['export', eid] as const, enabled: !!eid, queryFn: () => api.get<ExportDto>(`/exports/${eid}`),
    refetchInterval: (q) => (q.state.data?.status === 'running' ? 1500 : false),
  });
export const useExportPreview = (eid: string | null) =>
  useQuery({ queryKey: ['export', eid, 'preview'] as const, enabled: !!eid, queryFn: () => api.get<ExportPreviewDto>(`/exports/${eid}/preview`) });
/** Execution overview: refreshed every 2 s while the audit runs. */
export const useExecution = (aid: string, live: boolean) =>
  useQuery({ queryKey: qk.execution(aid), queryFn: () => api.get<ExecutionDto>(`/audits/${aid}/execution`), refetchInterval: live ? 2000 : false });
export const useSteps = (aid: string) => useQuery({ queryKey: qk.steps(aid), queryFn: () => api.get<StepDto[]>(`/audits/${aid}/steps`) });
export const useTrajectory = (aid: string, types: string[], q: string) =>
  useQuery({
    queryKey: qk.trajectory(aid, { types: [...types].sort(), q }),
    queryFn: () => api.get<TrajectoryPage>(`/audits/${aid}/trajectory${qs({ type: types, q: q || undefined, limit: '2000' })}`),
  });
export const useVulns = (pid: string, filters: Record<string, string | string[] | undefined>) =>
  useQuery({ queryKey: qk.vulns(pid, JSON.stringify(filters)), queryFn: () => api.get<Page<VulnSummaryDto>>(`/projects/${pid}/vulnerabilities${qs({ ...filters, limit: '200' })}`) });
export const useVuln = (vid: string | null) => useQuery({ queryKey: qk.vuln(vid ?? ''), queryFn: () => api.get<VulnDetailDto>(`/vulnerabilities/${vid}`), enabled: !!vid });
/** G1 review time of a project; refreshed with the vulnerability list after each decision. */
export const useReviewStats = (pid: string) => useQuery({ queryKey: ['vulns', pid, 'review-stats'], queryFn: () => api.get<ReviewStatsDto>(`/projects/${pid}/review-stats`) });
export const useRevisions = (vid: string) => useQuery({ queryKey: qk.revisions(vid), queryFn: () => api.get<RevisionDto[]>(`/vulnerabilities/${vid}/revisions`) });
export const useVulnLinks = (vid: string) =>
  useQuery({ queryKey: qk.links(vid), queryFn: () => api.get<{ auditId: string; auditTitle: string; findingId: string; findingNo: number | null; stepId: string; presence: string }[]>(`/vulnerabilities/${vid}/trajectory-links`) });
export const useSource = (aid: string, rid: string, path: string, from: number, to: number, enabled = true) =>
  useQuery({ queryKey: qk.source(aid, rid, path, from, to), queryFn: () => api.get<SourceDto>(`/audits/${aid}/repos/${encodeURIComponent(rid)}/source${qs({ path, from: String(from), to: String(to) })}`), enabled: enabled && !!path, staleTime: Infinity });
export const useTree = (aid: string, rid: string, path: string) =>
  useQuery({ queryKey: qk.tree(aid, rid, path), queryFn: () => api.get<TreeEntryDto[]>(`/audits/${aid}/repos/${encodeURIComponent(rid)}/tree${qs({ path: path || undefined })}`), staleTime: Infinity });
export const useGitCredentials = () => useQuery({ queryKey: qk.gitCredentials, queryFn: () => api.get<GitCredentialDto[]>('/settings/git-credentials') });
export const useProviders = () => useQuery({ queryKey: qk.providers, queryFn: () => api.get<ProviderDto[]>('/settings/model-providers') });
export const useModelSettings = () => useQuery({ queryKey: qk.models, queryFn: () => api.get<ModelSettingsDto>('/settings/models') });
export const useSceneDefaults = (scene: string) =>
  useQuery({ queryKey: qk.scene(scene), queryFn: () => api.get<{ scene: string; override: Record<string, unknown>; effective: unknown; revision: string; runnable: boolean }>(`/settings/scene-defaults/${scene}`) });
export const useGeneral = () => useQuery({ queryKey: qk.general, queryFn: () => api.get<GeneralSettingsDto>('/settings/general') });
export const useDiagnostics = () => useQuery({ queryKey: qk.diagnostics, queryFn: () => api.get<DiagnosticsDto>('/diagnostics') });
export const useKnowledge = (pid?: string) => useQuery({ queryKey: qk.knowledge(pid), queryFn: () => api.get<SkillDto[]>(`/knowledge${qs({ projectId: pid })}`) });
export const useRefs = (rid: string, kind: string, q: string, enabled: boolean) =>
  useQuery({ queryKey: qk.refs(rid, kind, q), queryFn: () => api.get<RefDto[]>(`/repos/${rid}/refs${qs({ kind: kind || undefined, q: q || undefined })}`), enabled });
export const probeRepo = (source: { path: string } | { git: string } | { uploadId: string }) => api.post<RepoProbeDto>('/repo-probes', source);

/** Mutation helper that invalidates the given keys on success. */
export function useInvalidatingMutation<V, R>(fn: (v: V) => Promise<R>, keys: readonly (readonly unknown[])[]) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: async () => {
      await Promise.all(keys.map((k) => qc.invalidateQueries({ queryKey: k as unknown[] })));
    },
  });
}

// Connectors
export const useConnectors = () => useQuery({ queryKey: ['connectors'], queryFn: () => api.get<ConnectorDto[]>('/connectors') });
export const usePushGuides = (pid: string, enabled = true) => useQuery({ queryKey: ['connectors', 'push-guides', pid], enabled, queryFn: () => api.get<PushGuideDto[]>(`/projects/${pid}/push-guides`) });
export const useVulnSync = (vid: string) => useQuery({ queryKey: ['vuln', vid, 'sync'], queryFn: () => api.get<SyncRecordDto[]>(`/vulnerabilities/${vid}/sync`) });
export const useProjectConnectors = (pid: string | undefined) => useQuery({ queryKey: ['connectors', 'project', pid], enabled: !!pid, queryFn: () => api.get<ProjectConnectorDto[]>(`/projects/${pid}/connectors`) });

// ---- conversations ----
export const useConversations = (status: 'active' | 'archived' = 'active') =>
  useQuery({ queryKey: qk.conversations(status), queryFn: () => api.get<ConversationDto[]>(`/conversations?status=${status}`) });
export const useConversation = (cid: string, opts: { enabled?: boolean } = {}) => useQuery({ queryKey: qk.conversation(cid), queryFn: () => api.get<ConversationDto>(`/conversations/${cid}`), enabled: opts.enabled ?? !!cid });
/** Latest 200 messages (a conversation rarely grows past that; older pages load on demand). */
export const useMessages = (cid: string, opts: { enabled?: boolean } = {}) => useQuery({ queryKey: qk.messages(cid), queryFn: () => api.get<MessagePageDto>(`/conversations/${cid}/messages?limit=200`), enabled: opts.enabled ?? !!cid });
/** Search by title or message text (conversation list, ⌘K). */
export const useConversationSearch = (q: string, enabled = true) =>
  useQuery({ queryKey: ['conversations', 'search', q], queryFn: () => api.get<ConversationDto[]>(`/conversations?q=${encodeURIComponent(q)}&limit=20`), enabled: enabled && q.trim().length > 0, staleTime: 5_000 });
/** The most recent active conversation that references an object (AI panel continuation). */
export const latestConversationAbout = async (kind: string, id: string): Promise<ConversationDto | null> =>
  (await api.get<ConversationDto[]>(`/conversations?status=active&mention=${kind}:${encodeURIComponent(id)}&limit=1`))[0] ?? null;
/** Risk hunts (sidebar and hunt list share the cache key). */
export const useHunts = () =>
  useQuery({ queryKey: ['hunts'], queryFn: () => api.get<HuntDto[]>('/hunts'), refetchInterval: (q) => (q.state.data?.some((h) => h.status === 'running') ? 2000 : false) });
export const useMentionCandidates = (q: string, enabled: boolean, types?: string) =>
  useQuery({ queryKey: ['mentions', q, types ?? ''], queryFn: () => api.get<MentionCandidateDto[]>(`/mention-candidates?q=${encodeURIComponent(q)}${types ? `&types=${types}` : ''}`), enabled, staleTime: 10_000 });
