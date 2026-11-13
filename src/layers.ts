import { type Credentials, fromBase64, isEncrypted, LockError, MARKER, open, seal, validateCredentials } from './crypto';
const encoder = new TextEncoder();
export const V2_MARKER = '<!--folder-lock:v2';
export interface Header extends Credentials {
  id: string; path: string; type: 'folder' | 'file'; sourcePath: string;
}
export interface Envelope {
  lockId: string; layers: string[]; payload: string; metadata: string;
  marker: string; headers: Header[];
}
const validId = (id: unknown): id is string => typeof id === 'string' && /^[a-f0-9]{32}$/.test(id);
export function newLockId(crypto: Crypto): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, '0')).join('');
}
export function validateHeader(value: unknown): Header {
  if (!value || typeof value !== 'object') throw new LockError('badFormat');
  const h = value as Record<string, unknown>;
  if (!validId(h.id) || typeof h.path !== 'string' || typeof h.sourcePath !== 'string' ||
      (h.type !== 'file' && h.type !== 'folder')) throw new LockError('badFormat');
  return { id: h.id, path: h.path, type: h.type, sourcePath: h.sourcePath, ...validateCredentials(h) };
}
export function parseEnvelope(text: string): Envelope | null {
  if (!isEncrypted(text)) return null;
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/);
  const marker = lines[0];
  if ((marker !== MARKER && marker !== V2_MARKER) || !lines[1] || !lines[2] ||
      (marker === V2_MARKER && lines[3] !== '-->')) throw new LockError('badFormat');
  let value: unknown;
  try { value = JSON.parse(lines[1]); } catch { throw new LockError('badFormat'); }
  if (!value || typeof value !== 'object') throw new LockError('badFormat');
  const v = value as Record<string, unknown>;
  if (!validId(v.lockId) || !Array.isArray(v.layers) || !v.layers.length ||
      v.layers.length > 128 || !v.layers.every(validId) || v.layers[0] !== v.lockId ||
      new Set(v.layers).size !== v.layers.length) throw new LockError('badFormat');
  if (fromBase64(lines[2]).length < 28) throw new LockError('badFormat');
  let headers: Header[] = [];
  if (marker === V2_MARKER) {
    if (!Array.isArray(v.headers) || v.headers.length !== v.layers.length) throw new LockError('badFormat');
    headers = v.headers.map(validateHeader);
    if (headers.some((h, i) => h.id !== (v.layers as string[])[i])) throw new LockError('badFormat');
  }
  const metadata = marker === V2_MARKER
    ? JSON.stringify({ lockId: v.lockId, layers: v.layers, headers })
    : JSON.stringify({ lockId: v.lockId, layers: v.layers });
  if (metadata !== lines[1]) throw new LockError('badFormat');
  return { lockId: v.lockId, layers: v.layers as string[], payload: lines[2], metadata, marker, headers };
}
function aad(marker: string, metadata: string): Uint8Array<ArrayBuffer> { return encoder.encode(`${marker}\n${metadata}`); }
/** Paths are renameable. KDF parameters, type, ID and verifier MUST agree with authenticated headers. */
export function assertHeaderMatches(header: Header, lock: Credentials & { id: string; type: string }): void {
  if (header.id !== lock.id || header.type !== lock.type || header.salt !== lock.salt ||
      header.iterations !== lock.iterations || header.verifier !== lock.verifier) throw new LockError('headerMismatch');
}
export async function decryptLayer(text: string, id: string, key: CryptoKey, crypto: Crypto): Promise<string> {
  const envelope = parseEnvelope(text);
  if (!envelope) return text;
  if (envelope.lockId !== id) throw new LockError('outerLocked');
  const plain = await open(envelope.payload, key, aad(envelope.marker, envelope.metadata), crypto);
  const inner = parseEnvelope(plain);
  const expected = envelope.layers.slice(1);
  if (JSON.stringify(inner?.layers ?? []) !== JSON.stringify(expected)) throw new LockError('badFormat');
  // Do not let an outer catalog disagree with the actual authenticated inner header.
  if (envelope.headers.length && inner?.headers.length &&
      JSON.stringify(envelope.headers.slice(1)) !== JSON.stringify(inner.headers)) throw new LockError('headerMismatch');
  return plain;
}
export async function encryptLayer(
  text: string, id: string, key: CryptoKey, crypto: Crypto, note: string,
  lock?: Credentials & { id: string; path: string; type: 'file' | 'folder' }, sourcePath?: string,
): Promise<string> {
  if (!validId(id)) throw new LockError('badMetadata');
  const inner = parseEnvelope(text);
  if (inner?.layers.includes(id)) return text;
  // A legacy inner layer lacks its salt; never advertise it as self-contained. Peel it first.
  if (lock && inner && !inner.headers.length) throw new LockError('legacyRecovery');
  const marker = lock ? V2_MARKER : MARKER;
  const headers = lock ? [{ id, path: lock.path, type: lock.type, sourcePath: sourcePath ?? lock.path,
    salt: lock.salt, verifier: lock.verifier, iterations: lock.iterations }, ...(inner?.headers ?? [])] : [];
  const metadata = lock
    ? JSON.stringify({ lockId: id, layers: [id, ...(inner?.layers ?? [])], headers })
    : JSON.stringify({ lockId: id, layers: [id, ...(inner?.layers ?? [])] });
  const payload = await seal(text, key, aad(marker, metadata), crypto);
  const encrypted = lock ? `${marker}\n${metadata}\n${payload}\n-->\n${note}\n` : `${marker}\n${metadata}\n${payload}\n${note}\n`;
  if (await decryptLayer(encrypted, id, key, crypto) !== text) throw new LockError('roundtripFailed');
  return encrypted;
}
