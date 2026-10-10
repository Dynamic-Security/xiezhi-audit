// Locating an installed command without a subprocess: the absolute path of a CLI or package runner.
import { accessSync, constants } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, isAbsolute, join } from 'node:path';

/** The absolute path of a command, looked up in PATH and the usual install directories (no subprocess). */
export function resolveCommand(command: string, extraDirs: string[] = []): string | null {
  const exec = (p: string) => { try { accessSync(p, constants.X_OK); return true; } catch { return false; } };
  if (isAbsolute(command)) return exec(command) ? command : null;
  const home = homedir();
  const dirs = [...extraDirs, ...(process.env.PATH ?? '').split(delimiter), join(home, '.local', 'bin'), '/opt/homebrew/bin', '/usr/local/bin', '/usr/bin', '/bin', join(home, '.volta', 'bin'), join(home, '.bun', 'bin')];
  for (const d of dirs) if (d && exec(join(d, command))) return join(d, command);
  return null;
}
