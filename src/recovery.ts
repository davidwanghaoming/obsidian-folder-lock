import { LockError } from './crypto';
import { isInFolders, normalizeFile, normalizeFolder, type Store } from './engine';
import { assertHeaderMatches, parseEnvelope, type Header } from './layers';
import { covers, type Lock } from './lock-engine';
export interface RecoveryResult { locks: Lock[]; legacyFiles: string[]; errors: string[]; found: number }
function recoveredPath(header: Header, actual: string, store: Store): string {
  normalizeFile(header.sourcePath); normalizeFolder(header.path);
  if (header.type === 'file') return normalizeFile(actual);
  if (!isInFolders(header.sourcePath, [header.path])) throw new LockError('badFormat');
  if (store.hasFolder(header.path) && isInFolders(actual, [header.path])) return header.path;
  const suffix = header.sourcePath.slice(header.path.length + 1);
  if (!actual.endsWith(`/${suffix}`)) throw new LockError('recoveryConflict');
  const folder = normalizeFolder(actual.slice(0, -suffix.length - 1));
  if (!store.hasFolder(folder)) throw new LockError('missingFolder');
  return folder;
}
/** Header contents are public, not trusted until password + GCM authentication succeeds. Never writes notes. */
export async function recoverHeaders(store: Store, existing: readonly Lock[] = []): Promise<RecoveryResult> {
  const found = new Map<string, Lock>();
  const result: RecoveryResult = { locks: [], legacyFiles: [], errors: [], found: 0 };
  for (const path of [...new Set(store.listFiles())].filter(p => /\.md$/i.test(p)).sort()) {
    try {
      const envelope = parseEnvelope(await store.read(path));
      if (!envelope) continue;
      if (!envelope.headers.length) { result.legacyFiles.push(path); continue; }
      for (const header of envelope.headers) {
        const recovered: Lock = { id: header.id, type: header.type, path: recoveredPath(header, path, store),
          salt: header.salt, verifier: header.verifier, iterations: header.iterations };
        const prior = found.get(header.id);
        if (prior) {
          assertHeaderMatches(header, prior);
          if (prior.path !== recovered.path) throw new LockError('recoveryConflict');
        }
        if (!covers(recovered, path)) throw new LockError('boundaryChanged');
        found.set(header.id, recovered);
      }
    } catch { result.errors.push(path); }
  }
  // Any disagreement aborts the entire recovery; do not half-rebuild a catalog.
  if (result.errors.length) { result.locks = [...existing]; return result; }
  const merged = existing.filter(l => !found.has(l.id));
  for (const lock of found.values()) {
    if (merged.some(l => l.path === lock.path && l.id !== lock.id)) throw new LockError('recoveryConflict');
    merged.push(lock);
  }
  if (new Set(merged.map(l => l.path)).size !== merged.length) throw new LockError('recoveryConflict');
  result.locks = merged; result.found = found.size;
  return result;
}
/** Prefer the file header's KDF and verifier; data.json is only an index/cache. */
export async function credentialsFromFiles(store: Store, locks: readonly Lock[], id: string): Promise<Lock> {
  const lock = locks.find(l => l.id === id); if (!lock) throw new LockError('unknownLock');
  let anchored: Lock | undefined;
  for (const path of store.listFiles().filter(p => /\.md$/i.test(p) && covers(lock, p))) {
    const envelope = parseEnvelope(await store.read(path));
    const header = envelope?.headers.find(h => h.id === id);
    if (!header) continue;
    assertHeaderMatches(header, lock);
    anchored = { ...lock, salt: header.salt, verifier: header.verifier, iterations: header.iterations };
  }
  return anchored ?? lock; // v0.1 and entirely unlocked layers still rely on their saved verifier.
}
