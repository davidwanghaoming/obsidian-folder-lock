import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createCredentials, LockError, unlockKey } from '../src/crypto';
import { encryptLayer, newLockId, parseEnvelope, V2_MARKER } from '../src/layers';
import { inspect, renameLocks, transformLocks, type Lock } from '../src/lock-engine';
import { credentialsFromFiles, recoverHeaders } from '../src/recovery';
import type { Store } from '../src/engine';
const crypto = webcrypto as unknown as Crypto;
const ready = Promise.all([createCredentials('outer-secret-1234', crypto), createCredentials('inner-secret-5678', crypto), createCredentials('attacker-secret', crypto)]);
class Memory implements Store {
  files = new Map([['secure/a.md', '秘密档案'], ['secure/empty.md', ''], ['other.md', 'unprotected']]);
  folders = new Set(['secure']); writes: string[] = [];
  listFiles(): string[] { return [...this.files.keys()]; }
  hasFolder(path: string): boolean { return this.folders.has(path); }
  async read(path: string): Promise<string> { return this.files.get(path)!; }
  async compareAndWrite(path: string, before: string, after: string): Promise<void> {
    if (this.files.get(path) !== before) throw new LockError('conflict');
    this.writes.push(path); this.files.set(path, after);
  }
}
async function setup() {
  const [a, b, attack] = await ready;
  const locks: Lock[] = [
    { id: newLockId(crypto), type: 'folder', path: 'secure', ...a.credentials },
    { id: newLockId(crypto), type: 'file', path: 'secure/a.md', ...b.credentials },
  ];
  const keys = new Map([[locks[0].id, a.key], [locks[1].id, b.key]]);
  return { locks, keys, store: new Memory(), attack };
}

test('v2 is self-contained with authenticated per-layer KDF catalog and minimal Markdown comment body', async () => {
  const { locks, keys, store } = await setup();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '🔒 已上锁');
  const text = store.files.get('secure/a.md')!, envelope = parseEnvelope(text)!;
  assert.ok(text.startsWith(`${V2_MARKER}\n`)); assert.ok(text.endsWith('-->\n🔒 已上锁\n'));
  assert.equal(envelope.headers.length, 2);
  for (const lock of locks) {
    const h = envelope.headers.find(h => h.id === lock.id)!;
    assert.equal(h.salt, lock.salt); assert.equal(h.iterations, 600_000); assert.equal(h.verifier, lock.verifier);
  }
  for (const secret of ['outer-secret-1234', 'inner-secret-5678', 'CryptoKey', '秘密档案']) assert.ok(!text.includes(secret));
});
test('deleted data.json can be rebuilt from public headers, then original passwords decrypt all layers', async () => {
  const { locks, keys, store } = await setup();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '🔒 已上锁');
  const before = [...store.files], writes = store.writes.length;
  const recovered = await recoverHeaders(store);
  assert.equal(recovered.found, 2); assert.deepEqual(recovered.errors, []);
  assert.deepEqual([...store.files], before); assert.equal(store.writes.length, writes);
  const recoveredKeys = new Map<string, CryptoKey>();
  for (const lock of recovered.locks) {
    const anchored = await credentialsFromFiles(store, recovered.locks, lock.id);
    recoveredKeys.set(lock.id, await unlockKey(lock.type === 'folder' ? 'outer-secret-1234' : 'inner-secret-5678', anchored, crypto));
  }
  const result = await transformLocks(store, recovered.locks, recovered.locks.map(l => l.id), 'unlock', recoveredKeys, crypto, '');
  assert.equal(result.failure, undefined); assert.equal(store.files.get('secure/a.md'), '秘密档案'); assert.equal(store.files.get('secure/empty.md'), '');
});
test('changing data.json salt, iterations OR verifier cannot decrypt or silently re-encrypt notes', async () => {
  const { locks, keys, store, attack } = await setup();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  for (const replacement of [{ salt: attack.credentials.salt }, { iterations: 310_000 }, { verifier: attack.credentials.verifier }]) {
    const changed = locks.map((l, i) => i === 0 ? { ...l, ...replacement } : l);
    const before = [...store.files], count = store.writes.length;
    const s = await inspect(store, changed);
    assert.ok(s.errors.some(e => e.code === 'headerMismatch'));
    await assert.rejects(credentialsFromFiles(store, changed, locks[0].id), (e: LockError) => e.code === 'headerMismatch');
    for (const mode of ['lock', 'unlock'] as const) {
      const result = await transformLocks(store, changed, [locks[0].id], mode, new Map([[locks[0].id, attack.key]]), crypto, '');
      assert.equal(result.failure?.code, 'headerMismatch'); assert.equal(result.phase, 'prepare');
    }
    assert.deepEqual([...store.files], before); assert.equal(store.writes.length, count);
  }
});
test('even replacing BOTH headers and data with attacker KDF/verifier fails GCM authentication', async () => {
  const { locks, keys, store, attack } = await setup();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  for (const [path, text] of [...store.files]) {
    const e = parseEnvelope(text); if (!e) continue;
    const lines = text.split('\n');
    const changed = JSON.parse(lines[1]);
    changed.headers = changed.headers.map((h: any) => h.id === locks[0].id ? { ...h, ...attack.credentials } : h);
    lines[1] = JSON.stringify(changed); store.files.set(path, lines.join('\n'));
  }
  const recovered = await recoverHeaders(store);
  assert.equal(recovered.errors.length, 0); // Public metadata is NOT claimed authenticated by recovery.
  const before = [...store.files], count = store.writes.length;
  const attackKeys = new Map(keys); attackKeys.set(locks[0].id, attack.key);
  const result = await transformLocks(store, recovered.locks, recovered.locks.map(l => l.id), 'unlock', attackKeys, crypto, '');
  assert.equal(result.failure?.code, 'authFailed'); assert.equal(result.phase, 'prepare');
  assert.deepEqual([...store.files], before); assert.equal(store.writes.length, count);
});
test('recovery infers whole-folder relocation from authenticated original source paths', async () => {
  const { locks, keys, store } = await setup();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  store.files = new Map([...store.files].map(([p, text]) => [p.replace(/^secure\//, 'moved/'), text]));
  store.folders = new Set(['moved']);
  const recovered = await recoverHeaders(store);
  assert.equal(recovered.errors.length, 0); assert.equal(recovered.locks.find(l => l.type === 'folder')?.path, 'moved');
  assert.equal(recovered.locks.find(l => l.type === 'file')?.path, 'moved/a.md');
  const result = await transformLocks(store, recovered.locks, recovered.locks.map(l => l.id), 'unlock', keys, crypto, '');
  assert.equal(result.failure, undefined); assert.equal(store.files.get('moved/a.md'), '秘密档案');
});
test('renames do not require re-encryption: KDF/header check ignores renameable scope paths', async () => {
  const { locks, keys, store } = await setup();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  const renamed = renameLocks(locks, 'secure/a.md', 'secure/renamed.md');
  store.files.set('secure/renamed.md', store.files.get('secure/a.md')!); store.files.delete('secure/a.md');
  const result = await transformLocks(store, renamed, renamed.map(l => l.id), 'unlock', keys, crypto, '');
  assert.equal(result.failure, undefined); assert.equal(store.files.get('secure/renamed.md'), '秘密档案');
});
test('conflicting catalog headers stop recovery without touching any file', async () => {
  const { locks, keys, store, attack } = await setup();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  const lines = store.files.get('secure/empty.md')!.split('\n');
  const value = JSON.parse(lines[1]); value.headers[0].salt = attack.credentials.salt; lines[1] = JSON.stringify(value);
  store.files.set('secure/empty.md', lines.join('\n'));
  const before = [...store.files];
  const recovered = await recoverHeaders(store, locks);
  assert.ok(recovered.errors.length); assert.equal(recovered.found, 0); assert.deepEqual([...store.files], before);
});
test('legacy 0.1 files still decrypt; full unlock+relock upgrades to recoverable v2', async () => {
  const { locks, keys, store } = await setup();
  const key = keys.get(locks[0].id)!;
  store.files.set('secure/a.md', await encryptLayer('秘密档案', locks[0].id, key, crypto, 'old'));
  const catalog = await recoverHeaders(store);
  assert.equal(catalog.found, 0); assert.deepEqual(catalog.legacyFiles, ['secure/a.md']);
  const plain = await transformLocks(store, [locks[0]], [locks[0].id], 'unlock', keys, crypto, '');
  assert.equal(plain.failure, undefined);
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '🔒 已上锁');
  assert.equal(parseEnvelope(store.files.get('secure/a.md')!)?.headers.length, 2);
});
test('dry-run authenticates every layer but performs no writes', async () => {
  const { locks, keys, store } = await setup();
  const before = [...store.files];
  const result = await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '', () => true, true);
  assert.equal(result.failure, undefined); assert.equal(store.writes.length, 0); assert.deepEqual([...store.files], before);
});
