// Add repositories: local directory, remote Git (https / ssh) or an uploaded archive.
// Each source is probed first (reachability, Git info, languages, auditable) before it can be added.
// RefPicker lists branches, tags and (local only) recent commits with keyword/hash search.
import { useEffect, useRef, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import type { DirectoryPickDto, RefDto, RepoDto, RepoProbeDto, UploadDto } from '@xiezhi/contracts';
import { api, ApiError, uploadFile } from '../../shared/api/client';
import { probeRepo, useRefs } from '../../shared/api/queries';
import { fmt } from '../../shared/format/messages';
import { Badge, Button, Dialog, Field, Icon, Progress, Segmented, Spinner, cx, ui, useToast } from '../../shared/ui';

type SourceKind = 'local' | 'git' | 'archive';

/** How a repository's default / chosen version reads (版本选择). */
export function versionLabel(repo: Pick<RepoDto, 'sourceKind' | 'sourceDetail'>, ref: string | null): string {
  if (repo.sourceKind === 'archive') return '包内内容';
  if (ref) return ref.length === 40 ? ref.slice(0, 7) : ref;
  if (repo.sourceKind === 'git') return `远程默认分支${repo.sourceDetail.defaultBranch ? `（${repo.sourceDetail.defaultBranch}）` : ''}`;
  return '当前工作区';
}

const errText = (e: unknown) => (e instanceof ApiError ? `${e.message}${e.hint ? `：${e.hint}` : ''}` : (e as Error).message);

export function AddRepoDialog({ pid, open, onClose }: { pid: string; open: boolean; onClose: () => void }) {
  const [kind, setKind] = useState<SourceKind>('local');
  const [path, setPath] = useState('');
  const [gitUrl, setGitUrl] = useState('');
  const [upload, setUpload] = useState<UploadDto | null>(null);
  const [progress, setProgress] = useState<{ loaded: number; total: number } | null>(null);
  const [name, setName] = useState('');
  const [ref, setRef] = useState('');
  const [probe, setProbe] = useState<RepoProbeDto | null>(null);
  const [probing, setProbing] = useState(false);
  const [picking, setPicking] = useState(false);
  const [pickNote, setPickNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const uploadAbort = useRef<AbortController | null>(null);
  const qc = useQueryClient();
  const toast = useToast();
  const reset = () => { setPath(''); setGitUrl(''); setUpload(null); setProgress(null); setName(''); setRef(''); setProbe(null); setErr(null); };
  useEffect(() => { if (!open) { uploadAbort.current?.abort(); reset(); setKind('local'); } }, [open]);

  // the service opens the system folder dialog on its machine and fills in the chosen path.
  const pickDir = async () => {
    setPicking(true); setPickNote(null);
    try {
      const r = await api.post<DirectoryPickDto>('/directory-picks', {});
      if (r.status === 'picked' && r.path) { setPath(r.path); setProbe(null); void runProbe({ path: r.path }); }
      else if (r.status === 'unavailable') setPickNote(`${r.reason ?? '无法打开系统目录选择窗口'}。请直接输入路径。`);
    } catch (e) {
      setPickNote(e instanceof ApiError ? e.message : '无法打开系统目录选择窗口，请直接输入路径。');
    } finally {
      setPicking(false);
    }
  };
  const runProbe = async (source: { path: string } | { git: string } | { uploadId: string }) => {
    setProbing(true);
    setErr(null);
    try {
      const p = await probeRepo(source);
      setProbe(p);
      if (!name) setName(p.suggestedName);
    } catch (e) {
      setErr(errText(e));
    } finally {
      setProbing(false);
    }
  };
  const pickFile = async (file: File | undefined) => {
    if (!file) return;
    setProbe(null);
    setUpload(null);
    setErr(null);
    const ac = new AbortController();
    uploadAbort.current = ac;
    try {
      const up = await uploadFile<UploadDto>(file, (loaded, total) => setProgress({ loaded, total }), ac.signal);
      setUpload(up);
      setProgress(null);
      await runProbe({ uploadId: up.uploadId });
    } catch (e) {
      setProgress(null);
      if (!ac.signal.aborted) setErr(errText(e));
    }
  };
  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      const source = kind === 'local' ? { path: path.trim() } : kind === 'git' ? { git: gitUrl.trim() } : { uploadId: upload!.uploadId };
      const r = await api.post<{ results: { ok: boolean; repo?: RepoDto; error?: { code: string; hint: string | null } }[] }>(`/projects/${pid}/repos`, {
        repos: [{ ...source, ...(name.trim() ? { name: name.trim() } : {}), ...(ref.trim() && kind !== 'archive' ? { ref: ref.trim() } : {}) }],
      });
      const first = r.results[0];
      if (!first?.ok) throw new Error(first?.error?.hint ?? first?.error?.code ?? '添加失败');
      await qc.invalidateQueries({ queryKey: ['project', pid] });
      await qc.invalidateQueries({ queryKey: ['projects'] });
      toast.ok(`已添加仓库 ${first.repo!.name}`);
      onClose();
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };
  const langs = probe ? Object.entries(probe.languages).sort((a, b) => b[1] - a[1]).slice(0, 6) : [];
  const refOptions = probe?.remote?.refs ?? [];
  const refHint = kind === 'git'
    ? `留空 = 远程默认分支${probe?.remote?.defaultBranch ? `（${probe.remote.defaultBranch}）` : ''}；可填分支、标签或完整 commit hash`
    : probe?.hasGit ? '留空 = 当前工作区（含未提交改动）；可填分支、标签或 commit' : '无 Git 信息，审计当前目录内容';
  return (
    <Dialog open={open} onClose={onClose} title="添加仓库" wide footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" disabled={!probe?.ok || probing} loading={busy} onClick={() => void submit()}>添加</Button>
    </>}>
      <Segmented value={kind} onChange={(k) => { reset(); setKind(k); }} items={[{ key: 'local', label: '本地目录' }, { key: 'git', label: 'Git 地址' }, { key: 'archive', label: '压缩包' }]} />
      {kind === 'local' && (
        <Field group label="本地目录" hint={picking ? '请在弹出的系统窗口中选择目录（可能在浏览器窗口后面）' : '服务所在机器上的绝对路径；也可以点“选择目录”在系统窗口中选择'}>
          <div className={ui.row}>
            <input aria-label="本地目录" className={cx(ui.input, ui.mono)} value={path} autoFocus placeholder="/path/to/repo" onChange={(e) => { setPath(e.target.value); setProbe(null); }}
              onBlur={() => { if (path.trim() && !probe && !probing) void runProbe({ path: path.trim() }); }} onKeyDown={(e) => { if (e.key === 'Enter' && path.trim()) void runProbe({ path: path.trim() }); }} />
            <Button icon="folder" onClick={() => void pickDir()} loading={picking} disabled={picking}>选择目录</Button>
            <Button onClick={() => { if (path.trim()) void runProbe({ path: path.trim() }); }} loading={probing}>检测</Button>
          </div>
          {pickNote && <div className={ui.faint} role="status" style={{ fontSize: 12, marginTop: 6 }}>{pickNote}</div>}
        </Field>
      )}
      {kind === 'git' && (
        <Field group label="Git 地址" hint="https://… 或 git@host:path。私有仓库：HTTPS 在“设置 › Git 凭证”中配置 token，SSH 使用本机密钥">
          <div className={ui.row}>
            <input aria-label="Git 地址" className={cx(ui.input, ui.mono)} value={gitUrl} autoFocus placeholder="https://github.com/org/repo.git" onChange={(e) => { setGitUrl(e.target.value); setProbe(null); }}
              onKeyDown={(e) => { if (e.key === 'Enter' && gitUrl.trim()) void runProbe({ git: gitUrl.trim() }); }} />
            <Button onClick={() => { if (gitUrl.trim()) void runProbe({ git: gitUrl.trim() }); }} loading={probing}>连接</Button>
          </div>
        </Field>
      )}
      {kind === 'archive' && (
        <Field group label="压缩包" hint="zip、tar、tar.gz；解压后不超过 2 GB、20 万个文件，单文件不超过 100 MB。包内符号链接不会还原">
          <div className={ui.row}>
            <input aria-label="压缩包文件" type="file" accept=".zip,.tar,.tgz,.tar.gz,application/zip,application/gzip,application/x-tar" disabled={!!progress}
              onChange={(e) => void pickFile(e.target.files?.[0])} />
            {progress && <Button size="sm" variant="ghost" onClick={() => uploadAbort.current?.abort()}>取消上传</Button>}
          </div>
          {progress && <div style={{ marginTop: 8 }}><Progress value={progress.loaded} max={progress.total} /><div className={ui.faint} style={{ fontSize: 12 }}>上传中 {Math.round((progress.loaded / Math.max(1, progress.total)) * 100)}%</div></div>}
          {upload && probing && <div className={ui.faint} style={{ fontSize: 12, marginTop: 8 }}><Spinner /> 正在检查压缩包…</div>}
        </Field>
      )}
      {probe && (
        <div className={ui.card} style={{ padding: 14 }}>
          <div className={cx(ui.row, ui.wrap)} style={{ marginBottom: 8 }}>
            {probe.ok ? <Badge tone="ok"><Icon name="check" size={12} />{kind === 'archive' ? '检查通过' : '可访问'}</Badge> : <Badge tone="danger">不可用</Badge>}
            {kind === 'local' && (probe.hasGit ? <Badge tone="info"><Icon name="git" size={12} />Git · {probe.currentBranch ?? 'detached'}</Badge> : probe.isDirectory && <Badge>无 Git 信息</Badge>)}
            {kind === 'git' && probe.ok && <Badge tone="info"><Icon name="git" size={12} />默认分支 · {probe.remote?.defaultBranch ?? '无'}</Badge>}
            {kind === 'git' && probe.ok && <Badge>{refOptions.filter((r) => r.kind === 'branch').length} 个分支 · {refOptions.filter((r) => r.kind === 'tag').length} 个标签</Badge>}
            {kind === 'archive' && probe.archive && probe.ok && <Badge>{probe.archive.format} · {probe.archive.fileCount} 个文件 · {fmt.bytes(probe.archive.totalBytes)}</Badge>}
            {probe.headCommit && <Badge><span className={ui.mono}>{probe.headCommit.slice(0, 7)}</span></Badge>}
            {probe.dirty && <Badge tone="warn">有未提交改动</Badge>}
            {probe.ok && (probe.auditable ? <Badge tone="accent">可审计</Badge> : <Badge tone="warn">上下文仓库</Badge>)}
          </div>
          {langs.length > 0 && <div className={ui.faint} style={{ fontSize: 12 }}>语言：{langs.map(([l, n]) => `${l} ${n}`).join(' · ')}</div>}
          {probe.problems.map((p) => <div key={p} className={ui.faint} style={{ fontSize: 12, marginTop: 4 }}>· {p}</div>)}
        </div>
      )}
      {probe?.ok && (
        <div style={{ display: 'grid', gridTemplateColumns: kind === 'archive' ? '1fr' : '1fr 1fr', gap: 12 }}>
          <Field label="仓库名称" hint="字母、数字、点、横线、下划线">
            <input className={ui.input} value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          {kind !== 'archive' && (
            <Field label="默认审计版本（可选）" hint={refHint}>
              <input className={cx(ui.input, ui.mono)} value={ref} list={kind === 'git' ? 'remote-refs' : undefined} disabled={kind === 'local' && !probe.hasGit}
                placeholder={kind === 'git' ? (probe.remote?.defaultBranch ?? 'main') : probe.hasGit ? '例如 main' : '—'} onChange={(e) => setRef(e.target.value)} />
              {kind === 'git' && <datalist id="remote-refs">{refOptions.slice(0, 200).map((r) => <option key={`${r.kind}:${r.name}`} value={r.name}>{r.kind === 'tag' ? '标签' : '分支'} · {r.commit.slice(0, 7)}</option>)}</datalist>}
            </Field>
          )}
        </div>
      )}
      {err && <div className={ui.error}>{err}</div>}
    </Dialog>
  );
}

export function RefPicker({ repoId, value, onPick, sourceKind = 'local', nullLabel }: {
  repoId: string; value: string | null; onPick: (ref: string | null) => void; sourceKind?: RepoDto['sourceKind'];
  /** Label of the "no ref" choice; hidden when onPick(null) makes no sense (e.g. a baseline). */
  nullLabel?: string | null;
}) {
  const [kind, setKind] = useState<'branch' | 'tag' | 'commit'>('branch');
  const [q, setQ] = useState('');
  const refs = useRefs(repoId, kind, q, sourceKind !== 'archive');
  const remote = sourceKind === 'git';
  const nullText = nullLabel === undefined ? (remote ? '使用远程默认分支' : '使用当前工作区') : nullLabel;
  if (sourceKind === 'archive') return <p className={ui.muted}>压缩包仓库没有分支或提交：审计的是上传时的包内内容。要换版本请重新上传。</p>;
  return (
    <div className={ui.stack}>
      <div className={ui.spread}>
        <Segmented value={kind} onChange={setKind} items={remote ? [{ key: 'branch', label: '分支' }, { key: 'tag', label: '标签' }] : [{ key: 'branch', label: '分支' }, { key: 'tag', label: '标签' }, { key: 'commit', label: '最近提交' }]} />
        {nullText && <Button size="sm" variant={value === null ? 'primary' : 'default'} onClick={() => onPick(null)}>{nullText}</Button>}
      </div>
      <input className={ui.input} placeholder="按名称、说明或 hash 搜索" value={q} onChange={(e) => setQ(e.target.value)} />
      <div style={{ maxHeight: 320, overflowY: 'auto', border: '1px solid var(--border)', borderRadius: 10 }}>
        {refs.isLoading && <div style={{ padding: 16 }}><Spinner /></div>}
        {refs.error && <div className={ui.error} style={{ margin: 12 }}>{errText(refs.error)}</div>}
        {refs.data?.length === 0 && <div className={ui.faint} style={{ padding: 16, fontSize: 13 }}>没有匹配项。也可以直接输入 commit hash{remote ? '（远程仓库需完整的 40 位 hash）' : ''}。</div>}
        {refs.data?.map((r: RefDto) => {
          const v = r.kind === 'commit' ? r.commit : r.name;
          return (
            <button key={`${r.kind}:${r.name}:${r.commit}`} className={ui.menuItem} style={{ borderRadius: 0, padding: '8px 12px', background: value === v ? 'var(--bg-active)' : undefined }} onClick={() => onPick(v)}>
              <Icon name={r.kind === 'commit' ? 'git' : r.kind === 'tag' ? 'target' : 'layers'} />
              <div className={ui.grow}>
                <div className={ui.ellipsis}><b>{r.kind === 'commit' ? r.commit.slice(0, 7) : r.name}</b> <span className={ui.muted}>{r.subject}</span></div>
                <div className={ui.faint} style={{ fontSize: 12 }}><span className={ui.mono}>{r.commit.slice(0, 7)}</span>{r.author && ` · ${r.author}`}{r.date && ` · ${fmt.date(r.date)}`}</div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function EditRefDialog({ repo, open, onClose }: { repo: RepoDto; open: boolean; onClose: () => void }) {
  const [manual, setManual] = useState('');
  const qc = useQueryClient();
  const toast = useToast();
  const save = async (ref: string | null) => {
    try {
      await api.patch(`/repos/${repo.id}`, { defaultRef: ref });
      await qc.invalidateQueries({ queryKey: ['project', repo.projectId] });
      toast.ok(`默认版本已设为 ${versionLabel(repo, ref)}`);
      onClose();
    } catch (e) { toast.error(e); }
  };
  return (
    <Dialog open={open} onClose={onClose} title={`默认审计版本 · ${repo.name}`} wide>
      <p className={ui.muted}>选择分支时，审计启动那一刻会解析为具体 commit 并固定下来。</p>
      <RefPicker repoId={repo.id} sourceKind={repo.sourceKind} value={repo.defaultRef} onPick={(r) => void save(r)} />
      {repo.sourceKind !== 'archive' && <div className={ui.row}>
        <input className={cx(ui.input, ui.mono)} placeholder="手工输入分支名或 commit hash" value={manual} onChange={(e) => setManual(e.target.value)} />
        <Button disabled={!manual.trim()} onClick={() => void save(manual.trim())}>使用</Button>
      </div>}
    </Dialog>
  );
}
