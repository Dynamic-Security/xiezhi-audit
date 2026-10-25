// Files added to a user message: images go to the model as images, text files (also those of an added
// folder) as data blocks of the message; anything else is refused. The bytes are artifacts; the message keeps
// their references, so editing, regenerating and the message list still have them. Later turns see only the names.
import { AppError, ATTACHMENT_LIMITS, IMAGE_MIME_TYPES, type AttachmentInput, type AttachmentKind } from '@xiezhi/contracts';
import { wrapUntrusted } from '@xiezhi/agent';
import { fromJson, type Store } from '@xiezhi/store';

export interface StoredAttachment { id: string; kind: AttachmentKind; name: string; mimeType: string; size: number }

/** Leading bytes of each accepted image type: the declared type is not trusted on its own. */
const MAGIC: Record<(typeof IMAGE_MIME_TYPES)[number], (b: Buffer) => boolean> = {
  'image/png': (b) => b.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])),
  'image/jpeg': (b) => b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff,
  'image/gif': (b) => /^GIF8[79]a/.test(b.subarray(0, 6).toString('latin1')),
  'image/webp': (b) => b.subarray(0, 4).toString('latin1') === 'RIFF' && b.subarray(8, 12).toString('latin1') === 'WEBP',
};

const isImageType = (t: string): t is (typeof IMAGE_MIME_TYPES)[number] => (IMAGE_MIME_TYPES as readonly string[]).includes(t);

/** Text when it decodes as UTF-8 without replacement characters or NUL bytes. */
function asText(b: Buffer): string | null {
  if (b.includes(0)) return null;
  try { return new TextDecoder('utf-8', { fatal: true }).decode(b); } catch { return null; }
}

/** Check and store the files of a message; `imagesAllowed` is false when the conversation's model takes text only. */
export function storeAttachments(store: Store, inputs: AttachmentInput[], imagesAllowed: boolean): StoredAttachment[] {
  if (inputs.length > ATTACHMENT_LIMITS.files) throw new AppError('COMMON_VALIDATION', `每条消息最多 ${ATTACHMENT_LIMITS.files} 个文件`);
  const out: StoredAttachment[] = [];
  let images = 0;
  let textBytes = 0;
  for (const f of inputs) {
    const bytes = Buffer.from(f.data, 'base64');
    if (isImageType(f.mimeType)) {
      if (!MAGIC[f.mimeType](bytes)) throw new AppError('COMMON_VALIDATION', `${f.name}：内容不是 ${f.mimeType} 图片`);
      if (!imagesAllowed) throw new AppError('COMMON_VALIDATION', `当前会话的模型不支持图片（${f.name}），可在设置的模型服务中为模型开启“支持图片”，或换用支持图片的模型`);
      if (bytes.length > ATTACHMENT_LIMITS.imageBytes) throw new AppError('COMMON_VALIDATION', `${f.name}：图片不能超过 ${ATTACHMENT_LIMITS.imageBytes >> 20} MB`);
      if (++images > ATTACHMENT_LIMITS.images) throw new AppError('COMMON_VALIDATION', `每条消息最多 ${ATTACHMENT_LIMITS.images} 张图片`);
      out.push({ id: store.artifacts.put(bytes, f.mimeType), kind: 'image', name: f.name, mimeType: f.mimeType, size: bytes.length });
      continue;
    }
    if (asText(bytes) === null) throw new AppError('COMMON_VALIDATION', `${f.name}：只能添加图片（png、jpeg、gif、webp）和文本文件`);
    if (bytes.length > ATTACHMENT_LIMITS.textBytes) throw new AppError('COMMON_VALIDATION', `${f.name}：文本文件不能超过 ${ATTACHMENT_LIMITS.textBytes >> 10} KB`);
    textBytes += bytes.length;
    if (textBytes > ATTACHMENT_LIMITS.totalTextBytes) throw new AppError('COMMON_VALIDATION', `每条消息的文本文件合计不能超过 ${ATTACHMENT_LIMITS.totalTextBytes >> 10} KB`);
    out.push({ id: store.artifacts.put(bytes, 'text/plain'), kind: 'text', name: f.name, mimeType: 'text/plain', size: bytes.length });
  }
  return out;
}

export const messageAttachments = (raw: string | null | undefined): StoredAttachment[] => fromJson<StoredAttachment[]>(raw ?? '[]', []);

/** The text files as data blocks: what the user added is material to examine, not instructions. */
export function attachmentText(store: Store, atts: StoredAttachment[], nonce: string): string {
  return atts.filter((a) => a.kind === 'text')
    .map((a) => wrapUntrusted(nonce, 'user_upload', a.name, store.artifacts.getText(a.id), a.id))
    .join('\n\n');
}

export function attachmentImages(store: Store, atts: StoredAttachment[]): { type: 'image'; data: string; mimeType: string }[] {
  return atts.filter((a) => a.kind === 'image').map((a) => ({ type: 'image', data: store.artifacts.get(a.id).toString('base64'), mimeType: a.mimeType }));
}

/** How a message's files read in the history of later turns. */
export const attachmentNote = (atts: StoredAttachment[]): string => (atts.length ? `（附件：${atts.map((a) => a.name).join('、')}）` : '');
