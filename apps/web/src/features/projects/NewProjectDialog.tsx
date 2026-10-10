import { useState } from 'react';
import { useNavigate } from '@tanstack/react-router';
import { useQueryClient } from '@tanstack/react-query';
import type { ProjectDto } from '@xiezhi/contracts';
import { api, ApiError } from '../../shared/api/client';
import { Button, Dialog, Field, ui, useToast } from '../../shared/ui';

/** Same rule as the service (names double as CLI identifiers); checked here to explain the problem in place. */
export function nameProblem(name: string): string | null {
  const n = name.trim();
  if (!n) return null;
  if (n.length > 100) return '项目名称最多 100 字';
  if (!/^[\p{L}\p{N}]/u.test(n)) return '项目名称需以字母、数字或中文开头';
  const bad = [...new Set([...n].filter((c) => !/[\p{L}\p{N}._ -]/u.test(c)))];
  return bad.length ? `项目名称不能包含：${bad.join(' ')}（可用横线或空格代替）` : null;
}

export function NewProjectDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [name, setName] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const qc = useQueryClient();
  const navigate = useNavigate();
  const toast = useToast();
  const problem = nameProblem(name);
  const submit = async () => {
    setBusy(true);
    setErr(null);
    try {
      const p = await api.post<ProjectDto>('/projects', { name: name.trim() });
      await qc.invalidateQueries({ queryKey: ['projects'] });
      toast.ok(`已创建项目 ${p.name}`);
      setName('');
      onClose();
      void navigate({ to: '/projects/$pid', params: { pid: p.id }, search: { tab: 'repos', addRepo: 1 } });
    } catch (e) {
      setErr(e instanceof ApiError ? `${e.message}${e.hint ? `：${e.hint}` : ''}` : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={open} onClose={onClose} title="新建项目" footer={<>
      <Button onClick={onClose}>取消</Button>
      <Button variant="primary" disabled={!name.trim() || !!problem} loading={busy} onClick={() => void submit()}>创建并添加仓库</Button>
    </>}>
      <p className={ui.muted}>一个项目对应一个业务系统，可以包含多个仓库。</p>
      <Field label="项目名称" error={problem ?? err} hint="字母、数字、中文、空格、点、横线、下划线，最多 100 字">
        <input className={ui.input} value={name} autoFocus placeholder="例如：订单系统" onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && !e.nativeEvent.isComposing && name.trim() && !problem) void submit(); }} />
      </Field>
    </Dialog>
  );
}
