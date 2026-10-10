// CLI I/O helpers: exit codes, secret input (TTY hidden / stdin / env), confirmation.
import { createInterface } from 'node:readline';
import { AppError } from '@xiezhi/contracts';

export const EXIT_OK = 0;
export const EXIT_ERROR = 2;
export const EXIT_INCOMPLETE = 3;

export class CliExit extends Error {
  constructor(readonly code: number, message: string) {
    super(message);
    this.name = 'CliExit';
  }
}

export function print(line = ''): void {
  process.stdout.write(line + '\n');
}

export function printJson(v: unknown): void {
  process.stdout.write(JSON.stringify(v, null, 2) + '\n');
}

export function errorLine(e: unknown): string {
  if (e instanceof AppError) return `错误 [${e.code}]：${e.message.replace(/^\w+: /, '')}`;
  if (e instanceof CliExit) return e.message;
  return `错误：${(e as Error).message}`;
}

/** Reject secrets on the command line (they end up in process lists and shell history). */
export function rejectSecretArgs(argv: string[]): void {
  const bad = argv.find((a) => /^--(api-?key|secret|token|password)(=|$)/i.test(a) || /^--[\w-]*key=/.test(a));
  if (bad) throw new AppError('SECRET_ON_COMMAND_LINE', `remove ${bad.split('=')[0]}; use "config set-secret" with a TTY prompt, stdin or --from-env`);
}

export async function readSecret(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    const chunks: Buffer[] = [];
    for await (const c of process.stdin) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString('utf8').trim();
  }
  return new Promise((resolve, reject) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    const out = rl as unknown as { _writeToOutput: (s: string) => void; output: NodeJS.WriteStream };
    process.stdout.write(prompt);
    out._writeToOutput = () => { /* hide typed characters */ };
    // A TTY readline swallows Ctrl+C (it emits 'SIGINT' on the interface instead of the process).
    rl.on('SIGINT', () => {
      rl.close();
      process.stdout.write('\n');
      reject(new CliExit(EXIT_ERROR, '已取消输入'));
    });
    rl.question('', (answer) => {
      rl.close();
      process.stdout.write('\n');
      resolve(answer.trim());
    });
  });
}

/** y/N prompt on a TTY; Ctrl+C or a closed stdin answers no. */
export async function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    let done = false;
    const finish = (v: boolean) => { if (done) return; done = true; rl.close(); resolve(v); };
    rl.on('SIGINT', () => { process.stdout.write('\n'); finish(false); });
    rl.on('close', () => finish(false));
    rl.question(`${question} [y/N] `, (a) => finish(/^y(es)?$/i.test(a.trim())));
  });
}

/**
 * Headless-mode Agent questions on a TTY: ask one at a time; an empty answer leaves the
 * question open (it never blocks the analysis). Ctrl+C is passed on to the process so the running
 * audit is interrupted as usual. Returns a stop function that closes the prompt.
 */
export function questionPrompter(answer: (questionId: string, text: string) => Promise<void>): { ask: (questionId: string, text: string) => void; stop: () => void } {
  if (!process.stdin.isTTY) return { ask: () => undefined, stop: () => undefined };
  const queue: { id: string; text: string }[] = [];
  let rl: ReturnType<typeof createInterface> | null = null;
  let stopped = false;
  const next = () => {
    if (stopped || rl || !queue.length) return;
    const q = queue.shift()!;
    rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    rl.on('SIGINT', () => { stop(); process.kill(process.pid, 'SIGINT'); });
    rl.question(`  回答 Agent（回车跳过，问题保持待回答）：`, (a) => {
      rl?.close();
      rl = null;
      const text = a.trim();
      const done = text ? answer(q.id, text).then(() => print('  已记录回答'), (e: Error) => print(`  回答未记录：${e.message}`)) : Promise.resolve();
      void done.finally(next);
    });
  };
  const stop = () => {
    stopped = true;
    queue.length = 0;
    rl?.close();
    rl = null;
  };
  return { ask: (id, text) => { queue.push({ id, text }); next(); }, stop };
}
