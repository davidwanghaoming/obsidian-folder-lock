import { decryptNote, encryptNote, isEncrypted, LockError, type ErrorCode } from './crypto';

export type Mode = 'lock' | 'unlock';
export interface Protection { folders: readonly string[]; files: readonly string[] }
export type Scope = readonly string[] | Protection;
export function protection(scope: Scope): Protection {
  return Array.isArray(scope) ? { folders: scope, files: [] } : scope as Protection;
}
export function isInScope(path: string, scope: Scope): boolean {
  const { folders, files } = protection(scope);
  return files.includes(path) || isInFolders(path, folders);
}
/** Update exact paths AND descendants when a parent directory moves. */
export function renamedPath(path: string, oldPath: string, newPath: string): string {
  return path === oldPath ? newPath : path.startsWith(`${oldPath}/`) ? `${newPath}${path.slice(oldPath.length)}` : path;
}
export interface Store {
  listFiles(): string[];
  hasFolder(path: string): boolean;
  read(path: string): Promise<string>;
  /** Must be an atomic equality check + replacement, e.g. Vault.process. */
  compareAndWrite(path: string, expected: string, replacement: string): Promise<void>;
}
export interface FileProblem { path: string; code: ErrorCode }
export interface Snapshot {
  plain: string[];
  encrypted: string[];
  nonMarkdown: string[];
  errors: FileProblem[];
}
export interface Report {
  mode: Mode;
  changed: string[];
  skipped: string[];
  state: Snapshot;
  failure?: FileProblem;
  phase: 'prepare' | 'write' | 'complete';
}
export function isInFolders(path: string, folders: readonly string[]): boolean {
  return folders.some(folder => path.startsWith(`${folder}/`));
}
export function normalizeFolder(path: string): string {
  const normalized = path.trim().replace(/\\/g, '/').replace(/\/+$/, '');
  if (!normalized || normalized.startsWith('/') || /[\x00-\x1F:]/.test(normalized) ||
      normalized.split('/').some(s => !s || s === '.' || s === '..' || s.startsWith('.'))) {
    throw new LockError('outsideFolder');
  }
  return normalized;
}
export function errorCode(error: unknown): ErrorCode {
  return error instanceof LockError ? error.code : 'ioFailed';
}
export function normalizeFile(path: string): string {
  const normalized = normalizeFolder(path);
  if (!/\.md$/i.test(normalized)) throw new LockError('outsideFolder');
  return normalized;
}
export async function scan(store: Store, scope: Scope): Promise<Snapshot> {
  const { folders, files } = protection(scope);
  const state: Snapshot = { plain: [], encrypted: [], nonMarkdown: [], errors: [] };
  for (const folder of folders) {
    if (!store.hasFolder(folder)) state.errors.push({ path: folder, code: 'missingFolder' });
  }
  const allFiles = [...new Set(store.listFiles())];
  for (const file of files) {
    if (!allFiles.includes(file)) state.errors.push({ path: file, code: 'missingFile' });
  }
  for (const path of allFiles.filter(p => isInScope(p, scope)).sort()) {
    if (!/\.md$/i.test(path)) { state.nonMarkdown.push(path); continue; }
    try {
      (isEncrypted(await store.read(path)) ? state.encrypted : state.plain).push(path);
    } catch (e) { state.errors.push({ path, code: errorCode(e) }); }
  }
  return state;
}

/**
 * Two phases: prepare and authenticate ALL files without writing; then CAS-write sequentially.
 * Not a transaction: a disk error/crash during phase 2 may leave a mixed state, reported explicitly.
 * No rollback (a rollback could overwrite concurrently edited notes or itself fail).
 */
export async function transformFolders(
  store: Store, scope: Scope, mode: Mode, key: CryptoKey, crypto: Crypto,
  lockedNote: string, canContinue: () => boolean = () => true,
): Promise<Report> {
  const { folders } = protection(scope);
  const report: Report = { mode, changed: [], skipped: [], phase: 'prepare', state: await scan(store, scope) };
  const plan: { path: string; before: string; after: string }[] = [];
  let current = '';
  try {
    for (const folder of folders) {
      current = folder;
      if (!store.hasFolder(folder)) throw new LockError('missingFolder');
    }
    if (report.state.errors.length) {
      current = report.state.errors[0].path;
      throw new LockError(report.state.errors[0].code);
    }
    const files = [...new Set(store.listFiles())].filter(p => isInScope(p, scope) && /\.md$/i.test(p)).sort();
    for (const path of files) {
      current = path;
      if (!canContinue()) throw new LockError('cancelled');
      const before = await store.read(path);
      if (mode === 'lock' && isEncrypted(before)) {
        // Authenticate existing ciphertext too; never silently accept an alien key/version.
        await decryptNote(before, key, crypto);
        report.skipped.push(path);
      } else if (mode === 'unlock' && !isEncrypted(before)) {
        report.skipped.push(path);
      } else {
        const after = mode === 'lock'
          ? await encryptNote(before, key, crypto, lockedNote)
          : await decryptNote(before, key, crypto);
        plan.push({ path, before, after });
      }
    }
    report.phase = 'write';
    for (const item of plan) {
      current = item.path;
      if (!canContinue()) throw new LockError('cancelled');
      // Recheck scope and existence immediately before each atomic write.
      if (!isInScope(item.path, scope)) throw new LockError('outsideFolder');
      await store.compareAndWrite(item.path, item.before, item.after);
      report.changed.push(item.path);
      // Drop staged plaintext references early. JS strings cannot be securely erased.
      item.before = ''; item.after = '';
    }
    report.phase = 'complete';
  } catch (e) {
    report.failure = { path: current, code: errorCode(e) };
  } finally {
    plan.length = 0;
  }
  // Re-read the actual current state, including late arrivals; never infer "locked" from key=null.
  report.state = await scan(store, scope);
  if (!report.failure && (report.state.errors.length ||
      (mode === 'lock' ? report.state.plain.length : report.state.encrypted.length))) {
    report.failure = report.state.errors[0] ?? {
      path: (mode === 'lock' ? report.state.plain : report.state.encrypted)[0], code: 'conflict',
    };
  }
  return report;
}
