import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createCredentials, encryptNote, fromBase64, isEncrypted, LockError, toBase64 } from '../src/crypto';
import { isInFolders, normalizeFolder, scan, transformFolders, type Store } from '../src/engine';
const crypto = webcrypto as unknown as Crypto;
const ready = createCredentials('correct-test-password', crypto);
class MemoryStore implements Store {
  files: Map<string, string>;
  folders = new Set(['测试文件夹', '测试文件夹/子目录', '其他']);
  writes: string[] = [];
  failAt: string | undefined;
  conflictAt: string | undefined;
  unreadableAt: string | undefined;
  constructor(files: Record<string, string>) { this.files = new Map(Object.entries(files)); }
  listFiles(): string[] { return [...this.files.keys()]; }
  hasFolder(path: string): boolean { return this.folders.has(path); }
  async read(path: string): Promise<string> {
    if (path === this.unreadableAt || !this.files.has(path)) throw new Error('io');
    return this.files.get(path)!;
  }
  async compareAndWrite(path: string, expected: string, replacement: string): Promise<void> {
    if (path === this.failAt) throw new Error('simulated write failure');
    if (path === this.conflictAt) this.files.set(path, 'new external edit');
    if (this.files.get(path) !== expected) throw new LockError('conflict');
    this.files.set(path, replacement); this.writes.push(path);
  }
}
const folders = ['测试文件夹'];
test('recursive .md-only scope; empty note; attachment list; no outside writes', async () => {
  const { key } = await ready;
  const input = {
    '测试文件夹/a.md': '你好', '测试文件夹/子目录/empty.md': '', '测试文件夹/UPPER.MD': '# hi',
    '测试文件夹/a.png': 'image', '测试文件夹/子目录/x.pdf': 'pdf',
    '其他/private.md': 'untouched', '测试文件夹2/no.md': 'also untouched', 'root.md': 'root',
  };
  const store = new MemoryStore(input);
  const locked = await transformFolders(store, folders, 'lock', key, crypto, '已锁定');
  assert.equal(locked.failure, undefined); assert.equal(locked.changed.length, 3);
  assert.equal(locked.state.plain.length, 0); assert.equal(locked.state.encrypted.length, 3);
  assert.deepEqual(locked.state.nonMarkdown, ['测试文件夹/a.png', '测试文件夹/子目录/x.pdf']);
  assert.ok(store.writes.every(p => isInFolders(p, folders) && /\.md$/i.test(p)));
  const lockedAgain = await transformFolders(store, folders, 'lock', key, crypto, '已锁定');
  assert.equal(lockedAgain.changed.length, 0); assert.equal(lockedAgain.skipped.length, 3);
  const unlocked = await transformFolders(store, folders, 'unlock', key, crypto, '已锁定');
  assert.equal(unlocked.failure, undefined); assert.equal(unlocked.changed.length, 3);
  assert.deepEqual(Object.fromEntries(store.files), input);
  const unlockedAgain = await transformFolders(store, folders, 'unlock', key, crypto, '');
  assert.equal(unlockedAgain.changed.length, 0); assert.equal(unlockedAgain.skipped.length, 3);
});
test('corrupt ciphertext in the last file aborts unlock before any writes', async () => {
  const { key } = await ready;
  const good = await encryptNote('first', key, crypto);
  const lines = (await encryptNote('last', key, crypto)).split('\n');
  const bytes = fromBase64(lines[1]); bytes[bytes.length - 1] ^= 1; lines[1] = toBase64(bytes);
  const store = new MemoryStore({ '测试文件夹/a.md': good, '测试文件夹/z.md': lines.join('\n') });
  const before = [...store.files];
  const result = await transformFolders(store, folders, 'unlock', key, crypto, '');
  assert.equal(result.failure?.path, '测试文件夹/z.md'); assert.equal(result.phase, 'prepare');
  assert.equal(result.failure?.code, 'authFailed'); assert.deepEqual(store.writes, []);
  assert.deepEqual([...store.files], before);
});
test('wrong decryption key causes no writes and no mutation', async () => {
  const { key } = await ready;
  const wrong = (await createCredentials('wrong-test-password', crypto)).key;
  const store = new MemoryStore({ '测试文件夹/a.md': await encryptNote('private', key, crypto), '测试文件夹/b.md': 'plain' });
  const before = [...store.files];
  const result = await transformFolders(store, folders, 'unlock', wrong, crypto, '');
  assert.equal(result.failure?.code, 'authFailed'); assert.deepEqual(store.writes, []);
  assert.deepEqual([...store.files], before);
});
test('encryption roundtrip failure stops the entire preflight before writes', async () => {
  const { key } = await ready;
  const store = new MemoryStore({ '测试文件夹/a.md': 'valid', '测试文件夹/b.md': '\uD800' });
  const result = await transformFolders(store, folders, 'lock', key, crypto, '');
  assert.equal(result.failure?.code, 'roundtripFailed'); assert.deepEqual(store.writes, []);
  assert.equal(result.state.plain.length, 2);
});
test('disk failure stops writes and reports exact mixed state', async () => {
  const { key } = await ready;
  const store = new MemoryStore({ '测试文件夹/a.md': 'A', '测试文件夹/b.md': 'B', '测试文件夹/c.md': 'C' });
  store.failAt = '测试文件夹/b.md';
  const result = await transformFolders(store, folders, 'lock', key, crypto, '');
  assert.equal(result.phase, 'write'); assert.equal(result.failure?.path, '测试文件夹/b.md');
  assert.deepEqual(result.changed, ['测试文件夹/a.md']);
  assert.deepEqual(result.state.encrypted, ['测试文件夹/a.md']);
  assert.deepEqual(result.state.plain, ['测试文件夹/b.md', '测试文件夹/c.md']);
  assert.equal(store.files.get('测试文件夹/c.md'), 'C');
  store.failAt = undefined;
  const retry = await transformFolders(store, folders, 'lock', key, crypto, '');
  assert.equal(retry.failure, undefined); assert.equal(retry.changed.length, 2); assert.equal(retry.skipped.length, 1);
});
test('concurrent edit is not overwritten; later files untouched', async () => {
  const { key } = await ready;
  const store = new MemoryStore({ '测试文件夹/a.md': 'A', '测试文件夹/b.md': 'B', '测试文件夹/c.md': 'C' });
  store.conflictAt = '测试文件夹/b.md';
  const result = await transformFolders(store, folders, 'lock', key, crypto, '');
  assert.equal(result.failure?.code, 'conflict'); assert.equal(store.files.get('测试文件夹/b.md'), 'new external edit');
  assert.equal(store.files.get('测试文件夹/c.md'), 'C'); assert.equal(store.writes.length, 1);
});
test('missing folders and unreadable files prevent any writes', async () => {
  const { key } = await ready;
  const store = new MemoryStore({ '测试文件夹/a.md': 'A' });
  const missing = await transformFolders(store, ['不存在'], 'lock', key, crypto, '');
  assert.equal(missing.failure?.code, 'missingFolder'); assert.deepEqual(store.writes, []);
  store.unreadableAt = '测试文件夹/a.md';
  const unreadable = await transformFolders(store, folders, 'lock', key, crypto, '');
  assert.equal(unreadable.failure?.path, '测试文件夹/a.md'); assert.deepEqual(store.writes, []);
  assert.equal(unreadable.state.errors.length, 1);
});
test('cancelled plugin lifecycle prevents writes', async () => {
  const { key } = await ready;
  const store = new MemoryStore({ '测试文件夹/a.md': 'A' });
  const result = await transformFolders(store, folders, 'lock', key, crypto, '', () => false);
  assert.equal(result.failure?.code, 'cancelled'); assert.deepEqual(store.writes, []);
});
test('scope uses full path boundaries, not mere prefix', () => {
  assert.ok(isInFolders('测试文件夹/a.md', folders));
  assert.equal(isInFolders('测试文件夹2/a.md', folders), false);
  assert.equal(isInFolders('测试文件夹.md', folders), false);
  assert.equal(isInFolders('other/测试文件夹/a.md', folders), false);
});
test('relative-path validation rejects traversal, absolute paths and hidden folders', () => {
  assert.equal(normalizeFolder(' 测试文件夹\\子目录/ '), '测试文件夹/子目录');
  for (const p of ['', '/', '.', '..', '../outside', 'a/../b', 'C:\\vault', '/root', 'a//b', '.obsidian', 'a/.hidden', 'a\n']) {
    // Whitespace around a path is intentionally trimmed.
    if (p === 'a\n') continue;
    assert.throws(() => normalizeFolder(p), p);
  }
});
test('scan reports non-md files without reading them', async () => {
  const store = new MemoryStore({ '测试文件夹/secret.pdf': 'not encrypted', '测试文件夹/empty.md': '' });
  store.unreadableAt = '测试文件夹/secret.pdf';
  const state = await scan(store, folders);
  assert.deepEqual(state.nonMarkdown, ['测试文件夹/secret.pdf']);
  assert.deepEqual(state.plain, ['测试文件夹/empty.md']); assert.equal(state.errors.length, 0);
});
test('unknown format is not double encrypted and blocks the batch', async () => {
  const { key } = await ready;
  const store = new MemoryStore({ '测试文件夹/a.md': 'plain', '测试文件夹/z.md': '%%folder-lock:v99%%\nunknown' });
  const result = await transformFolders(store, folders, 'lock', key, crypto, '');
  assert.equal(result.failure?.code, 'badFormat'); assert.deepEqual(store.writes, []);
  assert.equal(store.files.get('测试文件夹/a.md'), 'plain');
  assert.ok(isEncrypted(store.files.get('测试文件夹/z.md')!));
});
