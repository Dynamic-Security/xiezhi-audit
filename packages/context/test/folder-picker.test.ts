// Native folder picker: a fixed system program per platform, no shell; the answer is a path, a
// cancel, or “unavailable”. No real dialog is opened here: the commands are inspected and stand-in programs run.
import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { folderPickerCommand, pickFolder } from '@xiezhi/context';

const script = (body: string) => {
  const p = join(mkdtempSync(join(tmpdir(), 'ca-picker-')), 'pick.sh');
  writeFileSync(p, `#!/bin/sh\n${body}\n`);
  chmodSync(p, 0o755);
  return p;
};

describe('folder picker', () => {
  it('uses the system dialog of each platform, an absolute override, or none without a desktop session', () => {
    expect(folderPickerCommand('darwin', {})!.file).toBe('/usr/bin/osascript');
    expect(folderPickerCommand('darwin', {})!.args.join(' ')).toContain('choose folder');
    expect(folderPickerCommand('win32', { SystemRoot: 'C:\\Windows' })!.file).toBe('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe');
    expect(folderPickerCommand('win32', {})!.args.at(-1)).toContain('FolderBrowserDialog');
    expect(folderPickerCommand('linux', {})).toBeNull(); // no DISPLAY / WAYLAND_DISPLAY
    expect(folderPickerCommand('linux', { XIEZHI_AUDIT_FOLDER_PICKER: '/opt/pick' })).toEqual({ file: '/opt/pick', args: [] });
    expect(folderPickerCommand('darwin', { XIEZHI_AUDIT_FOLDER_PICKER: 'pick' })).toBeNull(); // relative: refused
  });

  it.skipIf(process.platform === 'win32')('returns the chosen path without its trailing slash; a cancel or an empty answer is a cancel', async () => {
    expect(await pickFolder({ file: script("printf '/tmp/some repo/\\n'"), args: [] })).toEqual({ status: 'picked', path: '/tmp/some repo' });
    expect(await pickFolder({ file: script("printf '/\\n'"), args: [] })).toEqual({ status: 'picked', path: '/' });
    expect(await pickFolder({ file: script('exit 1'), args: [] })).toEqual({ status: 'cancelled' });
    expect(await pickFolder({ file: script('exit 0'), args: [] })).toEqual({ status: 'cancelled' });
    expect(await pickFolder({ file: script('sleep 5'), args: [] }, 200)).toEqual({ status: 'cancelled' });
    expect((await pickFolder({ file: '/nonexistent/picker', args: [] })).status).toBe('unavailable');
    expect((await pickFolder(null)).status).toBe('unavailable');
  });
});
