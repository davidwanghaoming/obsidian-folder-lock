import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createCredentials, fromBase64, LockError, toBase64, unlockKey } from '../src/crypto';
import { decryptLayer, encryptLayer, newLockId, parseEnvelope } from '../src/layers';
import { inspect, neededKeys, operationLocks, renameLocks, transformLocks, type Lock } from '../src/lock-engine';
import type { Store } from '../src/engine';
const crypto = webcrypto as unknown as Crypto;
const ready = Promise.all([
  createCredentials('outer-password-密码', crypto), createCredentials('inner-password-秘密', crypto),
  createCredentials('nested-folder-password', crypto),
]).then(([outer, inner, nested]) => {
  const locks: Lock[] = [
    { id: newLockId(crypto), type: 'folder', path: '测试文件夹', ...outer.credentials },
    { id: newLockId(crypto), type: 'file', path: '测试文件夹/子目录/a.md', ...inner.credentials },
    { id: newLockId(crypto), type: 'folder', path: '测试文件夹/子目录', ...nested.credentials },
  ];
  return { locks, keys: new Map([[locks[0].id, outer.key], [locks[1].id, inner.key], [locks[2].id, nested.key]]) };
});
class StoreMock implements Store {
  files = new Map([['测试文件夹/子目录/a.md', '人物档案：中文\r\n'], ['测试文件夹/empty.md', ''],
    ['测试文件夹/image.png', 'attachment'], ['其他/no.md', 'outside']]);
  folders = new Set(['测试文件夹', '测试文件夹/子目录']);
  writes: string[] = [];
  failAt = '';
  conflictAt = '';
  listFiles(): string[] { return [...this.files.keys()]; }
  hasFolder(path: string): boolean { return this.folders.has(path); }
  async read(path: string): Promise<string> { if (!this.files.has(path)) throw new Error('read'); return this.files.get(path)!; }
  async compareAndWrite(path: string, before: string, after: string): Promise<void> {
    if (path === this.failAt) throw new Error('disk full');
    if (path === this.conflictAt) this.files.set(path, 'external edit');
    if (this.files.get(path) !== before) throw new LockError('conflict');
    this.files.set(path, after); this.writes.push(path);
  }
}

test('independent passwords/verifiers; wrong password per lock is rejected', async () => {
  const { locks } = await ready;
  assert.notEqual(locks[0].salt, locks[1].salt);
  await unlockKey('outer-password-密码', locks[0], crypto);
  await unlockKey('inner-password-秘密', locks[1], crypto);
  await assert.rejects(unlockKey('outer-password-密码', locks[1], crypto));
  await assert.rejects(unlockKey('inner-password-秘密', locks[0], crypto));
});
test('lock outer automatically applies folder + file inner layers first, with exact roundtrip', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock(), original = [...store.files];
  const r = await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '已锁定');
  assert.equal(r.failure, undefined); assert.equal(r.changed.length, 2);
  assert.deepEqual(parseEnvelope(store.files.get('测试文件夹/子目录/a.md')!)?.layers,
    [locks[0].id, locks[2].id, locks[1].id]);
  assert.equal(parseEnvelope(store.files.get('测试文件夹/empty.md')!)?.layers.length, 1);
  assert.equal(store.files.get('其他/no.md'), 'outside');
  assert.equal(store.files.get('测试文件夹/image.png'), 'attachment');
  assert.deepEqual(r.state.nonMarkdown, ['测试文件夹/image.png']);
  const unlocked = await transformLocks(store, locks, locks.map(l => l.id), 'unlock', keys, crypto, '');
  assert.equal(unlocked.failure, undefined); assert.deepEqual([...store.files], original);
});
test('unlocking only outer leaves inner encrypted, requiring the other passwords', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  const r = await transformLocks(store, locks, [locks[0].id], 'unlock', new Map([[locks[0].id, keys.get(locks[0].id)!]]), crypto, '');
  assert.equal(r.failure, undefined);
  assert.deepEqual(parseEnvelope(store.files.get('测试文件夹/子目录/a.md')!)?.layers, [locks[2].id, locks[1].id]);
  assert.equal(store.files.get('测试文件夹/empty.md'), '');
  await transformLocks(store, locks, [locks[2].id], 'unlock', keys, crypto, '');
  assert.deepEqual(parseEnvelope(store.files.get('测试文件夹/子目录/a.md')!)?.layers, [locks[1].id]);
  const last = await transformLocks(store, locks, [locks[1].id], 'unlock', keys, crypto, '');
  assert.equal(last.failure, undefined); assert.equal(store.files.get('测试文件夹/子目录/a.md'), '人物档案：中文\r\n');
});
test('unlock inner while outer locked is refused without touching any file', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  const before = [...store.files], writes = store.writes.length;
  await assert.rejects(neededKeys(store, locks, [locks[1].id], 'unlock'), (e: LockError) => e.code === 'outerLocked');
  const r = await transformLocks(store, locks, [locks[1].id], 'unlock', keys, crypto, '');
  assert.equal(r.failure?.code, 'outerLocked'); assert.equal(r.phase, 'prepare');
  assert.deepEqual([...store.files], before); assert.equal(store.writes.length, writes);
});
test('inner-first lock then outer, and locking the same visible/hidden layer twice is a no-op', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock();
  const one = await transformLocks(store, locks, [locks[1].id], 'lock', keys, crypto, '');
  assert.equal(one.failure, undefined); assert.equal(one.changed.length, 1);
  const inner = store.files.get('测试文件夹/子目录/a.md');
  const again = await transformLocks(store, locks, [locks[1].id], 'lock', keys, crypto, '');
  assert.equal(again.changed.length, 0); assert.equal(store.files.get('测试文件夹/子目录/a.md'), inner);
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  const outer = store.files.get('测试文件夹/子目录/a.md');
  const hidden = await transformLocks(store, locks, [locks[1].id], 'lock', new Map(), crypto, '');
  assert.equal(hidden.failure, undefined); assert.equal(hidden.changed.length, 0);
  assert.equal(store.files.get('测试文件夹/子目录/a.md'), outer);
  assert.deepEqual(await neededKeys(store, locks, [locks[0].id], 'lock'), []);
});
test('wrong outer or inner key aborts unlock-all preflight before any writes', async () => {
  const { locks, keys } = await ready;
  for (const wrongId of [locks[0].id, locks[1].id]) {
    const store = new StoreMock();
    await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
    const wrongKeys = new Map(keys);
    wrongKeys.set(wrongId, keys.get(wrongId === locks[0].id ? locks[1].id : locks[0].id)!);
    const before = [...store.files], writes = store.writes.length;
    const r = await transformLocks(store, locks, locks.map(l => l.id), 'unlock', wrongKeys, crypto, '');
    assert.equal(r.failure?.code, 'authFailed'); assert.equal(r.phase, 'prepare');
    assert.deepEqual([...store.files], before); assert.equal(store.writes.length, writes);
  }
});
test('clear metadata is authenticated and ciphertext tampering is rejected', async () => {
  const { locks, keys } = await ready;
  const id = locks[1].id, key = keys.get(id)!;
  const cipher = await encryptLayer('秘密', id, key, crypto, '');
  const lines = cipher.split('\n'), bytes = fromBase64(lines[2]); bytes[bytes.length - 1] ^= 1;
  lines[2] = toBase64(bytes);
  await assert.rejects(decryptLayer(lines.join('\n'), id, key, crypto));
  const metadata = cipher.split('\n');
  metadata[1] = JSON.stringify({ lockId: locks[0].id, layers: [locks[0].id] });
  await assert.rejects(decryptLayer(metadata.join('\n'), locks[0].id, key, crypto));
});
test('missing password prevents every planned write; standalone file scope is exact', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock();
  const r = await transformLocks(store, locks, [locks[0].id], 'lock', new Map(), crypto, '');
  assert.equal(r.failure?.code, 'passwordNeeded'); assert.deepEqual(store.writes, []);
  const one = await transformLocks(store, locks, [locks[1].id], 'lock', keys, crypto, '');
  assert.equal(one.changed.length, 1); assert.equal(store.files.get('测试文件夹/empty.md'), '');
  assert.equal(store.files.get('其他/no.md'), 'outside');
});
test('nested lock and unlock order is deterministic regardless of configuration order', async () => {
  const { locks } = await ready;
  assert.deepEqual(operationLocks([...locks].reverse(), [locks[0].id], 'lock').map(l => l.id), [locks[1].id, locks[2].id, locks[0].id]);
  assert.deepEqual(operationLocks(locks, locks.map(l => l.id), 'unlock').map(l => l.id), [locks[0].id, locks[2].id, locks[1].id]);
});
test('disk error and concurrent editing stop later writes and expose mixed state', async () => {
  const { locks, keys } = await ready;
  for (const conflict of [false, true]) {
    const store = new StoreMock();
    if (conflict) store.conflictAt = '测试文件夹/子目录/a.md'; else store.failAt = '测试文件夹/子目录/a.md';
    const r = await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
    assert.equal(r.phase, 'write'); assert.ok(r.failure);
    assert.equal(r.state.files.find(f => f.path === '测试文件夹/empty.md')?.layers.length, 1);
    assert.equal(r.state.files.find(f => f.path === '测试文件夹/子目录/a.md')?.layers.length, 0);
    assert.equal(store.files.get('其他/no.md'), 'outside');
  }
});
test('folder rename updates descendant entries; IDs, salt and keys remain stable and decrypt', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  const renamed = renameLocks(locks, '测试文件夹', '新目录');
  store.files = new Map([...store.files].map(([path, text]) => [path.replace(/^测试文件夹(?=\/)/, '新目录'), text]));
  store.folders = new Set(['新目录', '新目录/子目录']);
  assert.equal(renamed[1].path, '新目录/子目录/a.md');
  assert.equal(renamed[0].id, locks[0].id); assert.equal(renamed[0].salt, locks[0].salt);
  const r = await transformLocks(store, renamed, renamed.map(l => l.id), 'unlock', keys, crypto, '');
  assert.equal(r.failure, undefined); assert.equal(store.files.get('新目录/子目录/a.md'), '人物档案：中文\r\n');
});
test('single-file rename and unlocked cross-folder move update its path', async () => {
  const { locks } = await ready;
  const renamed = renameLocks(locks, locks[1].path, '其他/moved.md');
  assert.equal(renamed[1].path, '其他/moved.md'); assert.equal(renamed[0].path, locks[0].path);
  assert.equal(renamed[1].verifier, locks[1].verifier);
});
test('encrypted cross-boundary moves are reported, not decrypted with the wrong scope', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  const moved = renameLocks(locks, locks[1].path, '其他/moved.md');
  store.files.set('其他/moved.md', store.files.get(locks[1].path)!); store.files.delete(locks[1].path);
  const state = await inspect(store, moved);
  assert.equal(state.errors.find(e => e.path === '其他/moved.md')?.code, 'boundaryChanged');
  const before = [...store.files];
  const r = await transformLocks(store, moved, moved.map(l => l.id), 'unlock', keys, crypto, '');
  assert.equal(r.phase, 'prepare'); assert.ok(r.failure); assert.deepEqual([...store.files], before);
});
test('unknown/missing layer configuration never silently resets or overwrites ciphertext', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  const before = [...store.files];
  const r = await transformLocks(store, [locks[0]], [locks[0].id], 'unlock', keys, crypto, '');
  assert.equal(r.failure?.code, 'unknownLock'); assert.deepEqual([...store.files], before);
});
test('empty standalone note roundtrip and nested newline/BOM content are lossless', async () => {
  const { locks, keys } = await ready;
  const key = keys.get(locks[1].id)!;
  for (const text of ['', '\uFEFF你好\r\n  ', '中文🙂\n'.repeat(10_000)]) {
    const inner = await encryptLayer(text, locks[1].id, key, crypto, '');
    const outer = await encryptLayer(inner, locks[0].id, keys.get(locks[0].id)!, crypto, '');
    const peeled = await decryptLayer(outer, locks[0].id, keys.get(locks[0].id)!, crypto);
    assert.equal(await decryptLayer(peeled, locks[1].id, key, crypto), text);
  }
});
test('a locked standalone file can move to another folder and still decrypt with its own lock', async () => {
  const { locks, keys } = await ready;
  const originalLock = locks[1];
  const store = new StoreMock();
  await transformLocks(store, locks, [originalLock.id], 'lock', keys, crypto, '');
  const text = store.files.get(originalLock.path)!;
  store.files.delete(originalLock.path); store.files.set('其他/moved.md', text);
  const moved = renameLocks(locks, originalLock.path, '其他/moved.md');
  const r = await transformLocks(store, moved, [originalLock.id], 'unlock', keys, crypto, '');
  assert.equal(r.failure, undefined); assert.equal(store.files.get('其他/moved.md'), '人物档案：中文\r\n');
  assert.equal(store.files.get('测试文件夹/empty.md'), '');
});
test('production layer engine authenticates all notes before unlocking any of them', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock();
  await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  const lines = store.files.get(locks[1].path)!.split('\n');
  const bytes = fromBase64(lines[2]); bytes[bytes.length - 1] ^= 1; lines[2] = toBase64(bytes);
  store.files.set(locks[1].path, lines.join('\n'));
  const before = [...store.files], writes = store.writes.length;
  const r = await transformLocks(store, locks, locks.map(l => l.id), 'unlock', keys, crypto, '');
  assert.equal(r.failure?.code, 'authFailed'); assert.equal(r.phase, 'prepare');
  assert.deepEqual([...store.files], before); assert.equal(store.writes.length, writes);
});
test('production layer roundtrip rejection prevents writes to earlier valid notes too', async () => {
  const { locks, keys } = await ready;
  const store = new StoreMock(); store.files.set(locks[1].path, '\uD800');
  const r = await transformLocks(store, locks, [locks[0].id], 'lock', keys, crypto, '');
  assert.equal(r.failure?.code, 'roundtripFailed'); assert.equal(r.phase, 'prepare');
  assert.deepEqual(store.writes, []); assert.equal(store.files.get('测试文件夹/empty.md'), '');
});
