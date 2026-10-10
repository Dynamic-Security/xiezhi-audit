// Open the local workbench in the user's browser (`serve --open`). This is not an
// audit tool: it never sees audited code, only a loopback URL built by the service itself. The launcher
// is a fixed per-platform system program (or XIEZHI_AUDIT_BROWSER, an absolute path), no shell.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';

export interface BrowserCommand {
  file: string;
  args: string[];
}

/** Only the service's own loopback address may be opened. */
export function isLoopbackUrl(url: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  return u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '[::1]') && !u.username && !u.password;
}

const first = (paths: string[]) => paths.find((p) => existsSync(p)) ?? null;

export function browserCommand(url: string, platform: NodeJS.Platform = process.platform, override = process.env.XIEZHI_AUDIT_BROWSER): BrowserCommand | null {
  if (override) return isAbsolute(override) ? { file: override, args: [url] } : null;
  if (platform === 'darwin') return { file: '/usr/bin/open', args: [url] };
  if (platform === 'win32') {
    const root = process.env.SystemRoot ?? 'C:\\Windows';
    return { file: `${root}\\System32\\rundll32.exe`, args: ['url.dll,FileProtocolHandler', url] };
  }
  const xdg = first(['/usr/bin/xdg-open', '/usr/local/bin/xdg-open', '/bin/xdg-open']);
  return xdg ? { file: xdg, args: [url] } : null;
}

/**
 * Launch the browser detached; resolves true once the launcher started. The launcher gets the user's
 * environment (display/session variables are needed to reach the desktop browser).
 */
export function openBrowser(url: string): Promise<boolean> {
  if (!isLoopbackUrl(url)) return Promise.resolve(false);
  const cmd = browserCommand(url);
  if (!cmd) return Promise.resolve(false);
  return new Promise((resolve) => {
    try {
      const child = spawn(cmd.file, cmd.args, { shell: false, detached: true, stdio: 'ignore', env: process.env });
      child.once('error', () => resolve(false));
      child.once('spawn', () => {
        child.unref();
        resolve(true);
      });
    } catch {
      resolve(false);
    }
  });
}
