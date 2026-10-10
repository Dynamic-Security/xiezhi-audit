// Shown when there is no browser session: sessions come only from the one-time link
// printed by `xiezhi serve` or `xiezhi open`.
import { BrandMark, ui } from '../../shared/ui';

export function SessionRequired() {
  return (
    <div style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 24 }}>
      <div className={`${ui.card} ${ui.cardPad}`} style={{ maxWidth: 480, textAlign: 'center' }}>
        <div style={{ width: 48, margin: '0 auto 16px' }}><BrandMark size={48} /></div>
        <h1 style={{ fontSize: 20, marginBottom: 8 }}>需要登录会话</h1>
        <p className={ui.muted} style={{ marginBottom: 16 }}>
          为了防止其他网页冒用本机服务，浏览器只能通过一次性链接登录。请在终端运行下面的命令获取新的登录链接（5 分钟内有效，只能使用一次）。
        </p>
        <pre className={ui.code} style={{ padding: '10px 14px', textAlign: 'left' }}>xiezhi open</pre>
      </div>
    </div>
  );
}
