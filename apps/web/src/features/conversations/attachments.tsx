// Files added to a message: pasted, dropped or chosen files and folders, read in the browser and sent
// base64 with the message. Images and text files only; a folder's other files and its dependency / build
// directories are skipped. The server checks the same limits again (engine conversation/attachments.ts).
import type { AttachmentDto, AttachmentInput } from '@xiezhi/contracts';
import { Icon, cx } from '../../shared/ui';
import C from './conversations.module.css';

/** contracts `ATTACHMENT_LIMITS` and `IMAGE_MIME_TYPES` (web imports contracts types only). */
const ATTACHMENT_LIMITS = { files: 100, images: 5, imageBytes: 5 * 1024 * 1024, textBytes: 512 * 1024, totalTextBytes: 1024 * 1024 };
const IMAGE_MIME_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp'];

export interface PendingFile extends AttachmentInput { key: string; kind: 'image' | 'text'; size: number }

/** Directories of an added folder that are not the user's material. */
const SKIP_DIRS = new Set(['.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', 'target', '.next', '.idea', '.vscode']);

const isImage = (t: string) => IMAGE_MIME_TYPES.includes(t);

function base64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function isText(bytes: Uint8Array): boolean {
  if (bytes.includes(0)) return false;
  try { new TextDecoder('utf-8', { fatal: true }).decode(bytes); return true; } catch { return false; }
}

/** The path within an added folder, else the file name. */
const pathOf = (f: File) => f.webkitRelativePath || f.name;

/**
 * Read files for a message that already has `current`. From a folder, files that are not images or text, or over
 * a limit, are skipped quietly (listed in `skipped`); chosen one by one, each is refused with its reason.
 */
export async function readFiles(files: File[], current: PendingFile[], fromFolder: boolean): Promise<{ added: PendingFile[]; skipped: string[]; errors: string[] }> {
  const added: PendingFile[] = [];
  const skipped: string[] = [];
  const errors: string[] = [];
  let count = current.length;
  let images = current.filter((f) => f.kind === 'image').length;
  let text = current.filter((f) => f.kind === 'text').reduce((n, f) => n + f.size, 0);
  const refuse = (name: string, why: string) => { if (fromFolder) skipped.push(name); else errors.push(`${name}：${why}`); };
  for (const f of files) {
    const name = pathOf(f);
    if (fromFolder && name.split('/').slice(0, -1).some((d) => SKIP_DIRS.has(d))) continue;
    if (count >= ATTACHMENT_LIMITS.files) { refuse(name, `每条消息最多 ${ATTACHMENT_LIMITS.files} 个文件`); continue; }
    if (isImage(f.type)) {
      if (f.size > ATTACHMENT_LIMITS.imageBytes) { refuse(name, `图片不能超过 ${ATTACHMENT_LIMITS.imageBytes >> 20} MB`); continue; }
      if (images >= ATTACHMENT_LIMITS.images) { refuse(name, `每条消息最多 ${ATTACHMENT_LIMITS.images} 张图片`); continue; }
      images++; count++;
      added.push({ key: crypto.randomUUID(), kind: 'image', name: name === 'image.png' ? `粘贴的图片-${images}.png` : name, mimeType: f.type, size: f.size, data: base64(new Uint8Array(await f.arrayBuffer())) });
      continue;
    }
    if (f.size > ATTACHMENT_LIMITS.textBytes) { refuse(name, `文本文件不能超过 ${ATTACHMENT_LIMITS.textBytes >> 10} KB`); continue; }
    const bytes = new Uint8Array(await f.arrayBuffer());
    if (!isText(bytes)) { refuse(name, '只能添加图片（png、jpeg、gif、webp）和文本文件'); continue; }
    if (text + f.size > ATTACHMENT_LIMITS.totalTextBytes) { refuse(name, `文本文件合计不能超过 ${ATTACHMENT_LIMITS.totalTextBytes >> 10} KB`); continue; }
    text += f.size; count++;
    added.push({ key: crypto.randomUUID(), kind: 'text', name, mimeType: 'text/plain', size: f.size, data: base64(bytes) });
  }
  return { added, skipped, errors };
}

/** The request fields for `POST /conversations/{cid}/messages`. */
export const attachmentsBody = (files: PendingFile[]): { attachments?: AttachmentInput[] } =>
  (files.length ? { attachments: files.map((f) => ({ name: f.name, mimeType: f.mimeType, data: f.data })) } : {});

const kb = (n: number) => (n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${Math.round(n / 1024)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`);

/** Files of the message being written: image thumbnails and text file chips, each removable. */
export function PendingFiles({ files, onRemove }: { files: PendingFile[]; onRemove: (key: string) => void }) {
  if (!files.length) return null;
  return (
    <div className={C.files} aria-label="待发送的文件">
      {files.map((f) => (
        <span key={f.key} className={cx(C.file, f.kind === 'image' && C.fileImage)} title={`${f.name}（${kb(f.size)}）`}>
          {f.kind === 'image' ? <img src={`data:${f.mimeType};base64,${f.data}`} alt={f.name} /> : <><Icon name="file" size={12} /><span className={C.fileName}>{f.name}</span></>}
          <button className={C.fileX} aria-label={`移除文件 ${f.name}`} onClick={() => onRemove(f.key)}><Icon name="x" size={11} /></button>
        </span>
      ))}
    </div>
  );
}

/** Files of a sent message: images open full size, text files download. */
export function SentFiles({ messageId, files }: { messageId: string; files: AttachmentDto[] }) {
  if (!files.length) return null;
  const url = (a: AttachmentDto) => `/api/v1/messages/${messageId}/attachments/${a.id}`;
  return (
    <div className={cx(C.files, C.filesSent)} aria-label="消息附件">
      {files.map((a) => (
        <a key={a.id} className={cx(C.file, a.kind === 'image' && C.fileImage)} href={url(a)} target="_blank" rel="noopener noreferrer" title={`${a.name}（${kb(a.size)}）`}>
          {a.kind === 'image' ? <img src={url(a)} alt={a.name} /> : <><Icon name="file" size={12} /><span className={C.fileName}>{a.name}</span></>}
        </a>
      ))}
    </div>
  );
}
