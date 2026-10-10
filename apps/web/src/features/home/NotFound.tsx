import { Link } from '@tanstack/react-router';
import { EmptyState } from '../../shared/ui';

export function NotFound() {
  return <EmptyState icon="search" title="页面不存在或已失效" action={<Link to="/">返回工作台</Link>}>链接指向的对象可能已被删除。</EmptyState>;
}
