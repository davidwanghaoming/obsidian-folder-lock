/** Pure Web Crypto + portable text format. Never imports Obsidian or Node. */
export const MARKER = '%%folder-lock:v1%%';
export const PBKDF2_ITERATIONS = 600_000;
const IV_LENGTH = 12;
const SALT_LENGTH = 16;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const VERIFIER_TEXT = 'folder-lock password verifier v1';
const FILE_AAD = encoder.encode(MARKER);
const VERIFIER_AAD = encoder.encode('folder-lock:v1:password-verifier');

export type ErrorCode =
  | 'badFormat' | 'authFailed' | 'badMetadata' | 'roundtripFailed'
  | 'conflict' | 'outsideFolder' | 'missingFolder' | 'missingFile' | 'ioFailed' | 'cancelled' | 'outerLocked' | 'unknownLock' | 'passwordNeeded' | 'boundaryChanged' | 'headerMismatch' | 'legacyRecovery' | 'recoveryConflict';
export class LockError extends Error {
  constructor(public readonly code: ErrorCode) { super(code); this.name = 'LockError'; }
}
export interface Credentials { salt: string; verifier: string; iterations: number }

export function toBase64(bytes: Uint8Array): string {
  // No spread over an entire large note (argument limits on mobile).
  const chunks: string[] = [];
  for (let i = 0; i < bytes.length; i += 8192) {
    let part = '';
    for (const byte of bytes.subarray(i, i + 8192)) part += String.fromCharCode(byte);
    chunks.push(part);
  }
  return btoa(chunks.join(''));
}
export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  if (!text || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new LockError('badFormat');
  }
  try {
    const decoded = atob(text);
    const bytes = Uint8Array.from(decoded, c => c.charCodeAt(0));
    if (toBase64(bytes) !== text) throw new LockError('badFormat');
    return bytes;
  } catch { throw new LockError('badFormat'); }
}
/** Reserve ALL folder-lock versions, including malformed/unknown ones: never double-encrypt. */
export function isEncrypted(text: string): boolean {
  return /^\uFEFF?(?:%%folder-lock:|<!--folder-lock:)/.test(text);
}
export function validateCredentials(value: unknown): Credentials {
  if (typeof value !== 'object' || value === null) throw new LockError('badMetadata');
  const v = value as Record<string, unknown>;
  if (typeof v.salt !== 'string' || typeof v.verifier !== 'string' ||
      !Number.isInteger(v.iterations) || (v.iterations as number) < 310_000 || (v.iterations as number) > 10_000_000) throw new LockError('badMetadata');
  try {
    if (fromBase64(v.salt).length !== SALT_LENGTH || fromBase64(v.verifier).length < IV_LENGTH + 16) {
      throw new LockError('badMetadata');
    }
  } catch { throw new LockError('badMetadata'); }
  return { salt: v.salt, verifier: v.verifier, iterations: v.iterations as number };
}
export async function deriveKey(password: string, salt: string, crypto: Crypto, iterations = PBKDF2_ITERATIONS): Promise<CryptoKey> {
  if (!Number.isInteger(iterations) || iterations < 310_000 || iterations > 10_000_000) throw new LockError('badMetadata');
  const bytes = fromBase64(salt);
  if (bytes.length !== SALT_LENGTH) throw new LockError('badMetadata');
  const input = encoder.encode(password);
  try {
    const material = await crypto.subtle.importKey('raw', input, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: bytes, iterations },
      material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    );
  } finally { input.fill(0); }
}
export async function seal(text: string, key: CryptoKey, aad: Uint8Array<ArrayBuffer>, crypto: Crypto): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const bytes = encoder.encode(text);
  try {
    const cipher = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, bytes,
    ));
    const result = new Uint8Array(iv.length + cipher.length);
    result.set(iv); result.set(cipher, iv.length);
    return toBase64(result);
  } finally { bytes.fill(0); }
}
export async function open(payload: string, key: CryptoKey, aad: Uint8Array<ArrayBuffer>, crypto: Crypto): Promise<string> {
  const bytes = fromBase64(payload);
  if (bytes.length < IV_LENGTH + 16) throw new LockError('badFormat');
  try {
    const plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.slice(0, IV_LENGTH), additionalData: aad, tagLength: 128 },
      key, bytes.slice(IV_LENGTH),
    ));
    try { return decoder.decode(plain); } finally { plain.fill(0); }
  } catch { throw new LockError('authFailed'); }
}
export async function createCredentials(password: string, crypto: Crypto): Promise<{ credentials: Credentials; key: CryptoKey }> {
  const salt = toBase64(crypto.getRandomValues(new Uint8Array(SALT_LENGTH)));
  const key = await deriveKey(password, salt, crypto);
  const verifier = await seal(VERIFIER_TEXT, key, VERIFIER_AAD, crypto);
  const credentials = { salt, verifier, iterations: PBKDF2_ITERATIONS };
  // Ensure a usable verifier before this metadata is ever persisted.
  if (await open(verifier, key, VERIFIER_AAD, crypto) !== VERIFIER_TEXT) throw new LockError('roundtripFailed');
  return { credentials, key };
}
export async function unlockKey(password: string, value: Credentials, crypto: Crypto): Promise<CryptoKey> {
  const credentials = validateCredentials(value);
  const key = await deriveKey(password, credentials.salt, crypto, credentials.iterations);
  if (await open(credentials.verifier, key, VERIFIER_AAD, crypto) !== VERIFIER_TEXT) throw new LockError('authFailed');
  return key;
}
export async function decryptNote(text: string, key: CryptoKey, crypto: Crypto): Promise<string> {
  if (!isEncrypted(text)) return text; // Includes the empty string.
  const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/);
  if (lines[0] !== MARKER || !lines[1]) throw new LockError('badFormat');
  return open(lines[1], key, FILE_AAD, crypto);
}
export async function encryptNote(text: string, key: CryptoKey, crypto: Crypto, lockedNote = ''): Promise<string> {
  if (isEncrypted(text)) return text;
  const result = `${MARKER}\n${await seal(text, key, FILE_AAD, crypto)}\n${lockedNote}\n`;
  if (await decryptNote(result, key, crypto) !== text) throw new LockError('roundtripFailed');
  return result;
}
