import { type Credentials, LockError } from './crypto';
import { assertHeaderMatches, decryptLayer, encryptLayer, parseEnvelope } from './layers';
import { errorCode, isInFolders, renamedPath, type FileProblem, type Mode, type Store } from './engine';
export interface Lock extends Credentials { id: string; path: string; type: 'folder' | 'file' }
export interface FileState { path: string; layers: string[] }
export interface LockState { id: string; applied: number; clear: number; blocked: number; errors: number }
export interface State {
  files: FileState[];
  nonMarkdown: string[];
  errors: FileProblem[];
  locks: LockState[];
}
export interface LayerReport {
  mode: Mode; changed: string[]; skipped: string[]; state: State;
  failure?: FileProblem; phase: 'prepare' | 'write' | 'complete';
}
export function covers(lock: Lock, path: string): boolean {
  return lock.type === 'file' ? lock.path === path : isInFolders(path, [lock.path]);
}
export function isOuter(outer: Lock, inner: Lock): boolean {
  return outer.type === 'folder' && outer.id !== inner.id && isInFolders(inner.path, [outer.path]);
}
function depth(lock: Lock): number { return lock.path.split('/').length * 2 + (lock.type === 'file' ? 1 : 0); }
function stack(text: string, locks: readonly Lock[], path: string): string[] {
  const envelope = parseEnvelope(text);
  const layers = envelope?.layers ?? [];
  for (const header of envelope?.headers ?? []) {
    const lock = locks.find(l => l.id === header.id);
    if (!lock) throw new LockError('unknownLock');
    assertHeaderMatches(header, lock);
  }
  for (let i = 0; i < layers.length; i++) {
    const lock = locks.find(l => l.id === layers[i]);
    if (!lock) throw new LockError('unknownLock');
    if (!covers(lock, path)) throw new LockError('boundaryChanged');
    const next = locks.find(l => l.id === layers[i + 1]);
    if (next && !isOuter(lock, next)) throw new LockError('badFormat');
  }
  return layers;
}
export function operationLocks(locks: readonly Lock[], ids: readonly string[], mode: Mode): Lock[] {
  const direct = locks.filter(l => ids.includes(l.id));
  if (direct.length !== new Set(ids).size) throw new LockError('unknownLock');
  // Locking an outer lock first ensures every nested lock is applied; unlocking only peels requested layers.
  const targets = mode === 'lock' ? locks.filter(l => direct.some(d => d.id === l.id || isOuter(d, l))) : direct;
  return [...targets].sort((a, b) => (mode === 'lock' ? depth(b) - depth(a) : depth(a) - depth(b)) || a.id.localeCompare(b.id));
}
export async function inspect(store: Store, locks: readonly Lock[]): Promise<State> {
  const state: State = { files: [], nonMarkdown: [], errors: [], locks: locks.map(l => ({ id: l.id, applied: 0, clear: 0, blocked: 0, errors: 0 })) };
  const paths = [...new Set(store.listFiles())].sort();
  for (const lock of locks) {
    if (lock.type === 'folder' ? !store.hasFolder(lock.path) : !paths.includes(lock.path)) {
      state.errors.push({ path: lock.path, code: lock.type === 'folder' ? 'missingFolder' : 'missingFile' });
    }
  }
  for (const path of paths.filter(p => locks.some(l => covers(l, p)))) {
    if (!/\.md$/i.test(path)) { state.nonMarkdown.push(path); continue; }
    try { state.files.push({ path, layers: stack(await store.read(path), locks, path) }); }
    catch (e) { state.errors.push({ path, code: errorCode(e) }); }
  }
  for (const lock of locks) {
    const s = state.locks.find(l => l.id === lock.id)!;
    s.errors = state.errors.filter(e => e.path === lock.path || covers(lock, e.path)).length;
    for (const file of state.files.filter(f => covers(lock, f.path))) {
      const blocked = file.layers.some(id => { const l = locks.find(l => l.id === id); return l && isOuter(l, lock); });
      if (blocked) s.blocked++;
      if (file.layers.includes(lock.id)) s.applied++;
      else if (!blocked) s.clear++;
    }
  }
  return state;
}
export async function neededKeys(store: Store, locks: readonly Lock[], ids: readonly string[], mode: Mode): Promise<string[]> {
  const targets = operationLocks(locks, ids, mode);
  const needed = new Set<string>();
  for (const lock of targets) {
    if (lock.type === 'folder' ? !store.hasFolder(lock.path) : !store.listFiles().includes(lock.path)) {
      throw new LockError(lock.type === 'folder' ? 'missingFolder' : 'missingFile');
    }
  }
  for (const path of [...new Set(store.listFiles())].filter(p => /\.md$/i.test(p) && targets.some(l => covers(l, p))).sort()) {
    const layers = stack(await store.read(path), locks, path);
    for (const lock of targets.filter(l => covers(l, path))) {
      const applied = layers.includes(lock.id);
      if (mode === 'lock' ? !applied : applied) needed.add(lock.id);
      // A single inner unlock must not silently succeed behind a locked outer layer.
      if (mode === 'unlock' && layers.some(id => {
        const outer = locks.find(l => l.id === id);
        return outer && isOuter(outer, lock) && !targets.some(t => t.id === id);
      })) throw new LockError('outerLocked');
    }
  }
  return targets.filter(l => needed.has(l.id)).map(l => l.id);
}
export async function transformLocks(
  store: Store, locks: readonly Lock[], ids: readonly string[], mode: Mode,
  keys: ReadonlyMap<string, CryptoKey>, crypto: Crypto, note: string, canContinue: () => boolean = () => true, dryRun = false,
): Promise<LayerReport> {
  const report: LayerReport = { mode, changed: [], skipped: [], state: await inspect(store, locks), phase: 'prepare' };
  const plan: { path: string; before: string; after: string }[] = [];
  let current = '';
  try {
    const targets = operationLocks(locks, ids, mode);
    const relevantError = report.state.errors.find(e => targets.some(l => e.path === l.path || covers(l, e.path)));
    if (relevantError) { current = relevantError.path; throw new LockError(relevantError.code); }
    for (const path of [...new Set(store.listFiles())].filter(p => /\.md$/i.test(p) && targets.some(l => covers(l, p))).sort()) {
      current = path;
      if (!canContinue()) throw new LockError('cancelled');
      const before = await store.read(path);
      let after = before;
      for (const lock of targets.filter(l => covers(l, path))) {
        const layers = stack(after, locks, path);
        const outerPresent = layers.some(id => { const outer = locks.find(l => l.id === id); return outer && isOuter(outer, lock); });
        if (mode === 'lock') {
          if (layers.includes(lock.id)) continue;
          if (outerPresent) throw new LockError('outerLocked');
          const key = keys.get(lock.id); if (!key) throw new LockError('passwordNeeded');
          after = await encryptLayer(after, lock.id, key, crypto, note, lock, path);
        } else {
          if (outerPresent) throw new LockError('outerLocked');
          if (!layers.includes(lock.id)) continue;
          const key = keys.get(lock.id); if (!key) throw new LockError('passwordNeeded');
          after = await decryptLayer(after, lock.id, key, crypto);
        }
      }
      if (after === before) report.skipped.push(path); else plan.push({ path, before, after });
    }
    if (dryRun) { report.phase = 'complete'; return report; }
    report.phase = 'write';
    for (const item of plan) {
      current = item.path;
      if (!canContinue()) throw new LockError('cancelled');
      await store.compareAndWrite(item.path, item.before, item.after);
      report.changed.push(item.path); item.before = ''; item.after = '';
    }
    report.phase = 'complete';
  } catch (e) { report.failure = { path: current, code: errorCode(e) }; }
  finally { plan.length = 0; }
  report.state = await inspect(store, locks);
  if (!report.failure) {
    const targets = operationLocks(locks, ids, mode);
    const error = report.state.errors.find(e => targets.some(l => e.path === l.path || covers(l, e.path)));
    const conflict = report.state.files.find(file => targets.some(lock => covers(lock, file.path) &&
      (mode === 'lock' ? !file.layers.includes(lock.id) : file.layers.includes(lock.id))));
    if (error || conflict) report.failure = error ?? { path: conflict!.path, code: 'conflict' };
  }
  return report;
}
export function renameLocks(locks: readonly Lock[], oldPath: string, newPath: string): Lock[] {
  return locks.map(lock => ({ ...lock, path: renamedPath(lock.path, oldPath, newPath) }));
}
