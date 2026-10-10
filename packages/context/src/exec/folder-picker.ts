// Native folder picker for “添加仓库 › 本地目录”. A web page cannot learn a folder's absolute path,
// so the local service opens the operating system's own dialog and returns the chosen path. Like `browser.ts`, this
// is not an audit tool and never sees audited code: a fixed per-platform system program with a fixed script, no
// shell, no user-provided arguments. The path is only filled into the form; the user still checks and adds it.
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { isAbsolute } from 'node:path';

export interface FolderPickerCommand {
  file: string;
  args: string[];
}

export type FolderPick =
  | { status: 'picked'; path: string }
  | { status: 'cancelled' }
  | { status: 'unavailable'; reason: string };

const PROMPT = '选择要审计的代码目录';
/** A dialog left open longer than this is treated as cancelled. */
const PICK_TIMEOUT_MS = 10 * 60_000;

const first = (paths: string[]) => paths.find((p) => existsSync(p)) ?? null;

/**
 * The dialog program of this platform, or null (with no desktop session on Linux, or no zenity / kdialog).
 * `XIEZHI_AUDIT_FOLDER_PICKER` (an absolute path, like `XIEZHI_AUDIT_BROWSER`) replaces it, e.g. in tests.
 */
export function folderPickerCommand(platform: NodeJS.Platform = process.platform, env: NodeJS.ProcessEnv = process.env): FolderPickerCommand | null {
  const override = env.XIEZHI_AUDIT_FOLDER_PICKER;
  if (override) return isAbsolute(override) ? { file: override, args: [] } : null;
  if (platform === 'darwin') {
    // `activate` brings the dialog in front of the browser; cancelling exits with -128.
    return { file: '/usr/bin/osascript', args: ['-e', 'activate', '-e', `POSIX path of (choose folder with prompt "${PROMPT}")`] };
  }
  if (platform === 'win32') {
    const root = env.SystemRoot ?? 'C:\\Windows';
    const script = [
      'Add-Type -AssemblyName System.Windows.Forms',
      '$d = New-Object System.Windows.Forms.FolderBrowserDialog',
      `$d.Description = '${PROMPT}'`,
      '$d.ShowNewFolderButton = $false',
      "$f = New-Object System.Windows.Forms.Form -Property @{TopMost = $true}",
      "if ($d.ShowDialog($f) -eq 'OK') { [Console]::OutputEncoding = [Text.Encoding]::UTF8; [Console]::Out.Write($d.SelectedPath) }",
    ].join('; ');
    return { file: `${root}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`, args: ['-NoProfile', '-NonInteractive', '-STA', '-Command', script] };
  }
  if (!env.DISPLAY && !env.WAYLAND_DISPLAY) return null;
  const zenity = first(['/usr/bin/zenity', '/usr/local/bin/zenity']);
  if (zenity) return { file: zenity, args: ['--file-selection', '--directory', `--title=${PROMPT}`] };
  const kdialog = first(['/usr/bin/kdialog', '/usr/local/bin/kdialog']);
  if (kdialog) return { file: kdialog, args: ['--getexistingdirectory', env.HOME ?? '/', '--title', PROMPT] };
  return null;
}

/**
 * Open the dialog and wait for the user. An empty answer or a non-zero exit is a cancel (all three platforms report
 * a cancel that way); a launcher that cannot start is “unavailable”.
 */
export function pickFolder(cmd: FolderPickerCommand | null = folderPickerCommand(), timeoutMs = PICK_TIMEOUT_MS): Promise<FolderPick> {
  if (!cmd) return Promise.resolve({ status: 'unavailable', reason: '这台机器上没有可用的系统目录选择窗口（无桌面会话，或 Linux 未安装 zenity / kdialog）' });
  return new Promise((resolve) => {
    let out = '';
    let settled = false;
    const done = (r: FolderPick) => { if (!settled) { settled = true; clearTimeout(timer); resolve(r); } };
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(cmd.file, cmd.args, { shell: false, stdio: ['ignore', 'pipe', 'ignore'], env: process.env, windowsHide: false });
    } catch (e) {
      resolve({ status: 'unavailable', reason: `无法打开系统目录选择窗口：${(e as Error).message}` });
      return;
    }
    const timer = setTimeout(() => { child.kill(); done({ status: 'cancelled' }); }, timeoutMs);
    child.stdout!.setEncoding('utf8');
    child.stdout!.on('data', (d: string) => { if (out.length < 8192) out += d; });
    child.once('error', (e) => done({ status: 'unavailable', reason: `无法打开系统目录选择窗口：${e.message}` }));
    child.once('close', (code) => {
      const path = out.replace(/[\r\n]+$/, '');
      // macOS returns a trailing slash for folders; a root (`/`, `C:\\`) keeps its own.
      done(code === 0 && path ? { status: 'picked', path: path.replace(/(?<=[^\\/:])[\\/]+$/, '') } : { status: 'cancelled' });
    });
  });
}
