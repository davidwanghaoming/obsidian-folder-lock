import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { createCredentials, unlockKey } from '../src/crypto';
import { newLockId, parseEnvelope } from '../src/layers';
import { inspect, type Lock } from '../src/lock-engine';
import type { Store } from '../src/engine';
import FolderLockPlugin from '../src/main';
// This import is aliased ONLY in the test bundle, never in the production plugin.
import { Notice, TFile, TFolder } from './obsidian-mock';
const crypto = webcrypto as unknown as Crypto;
const ready = Promise.all([createCredentials('outer-pass-1234', crypto), createCredentials('inner-pass-5678', crypto)]);
interface Harness {
  keys: Map<string, CryptoKey>;
  accessReady: boolean;
  readyResolve: () => void;
  updateHeaderCatalog: () => Promise<void>;
  promptPassword: (lock: Lock) => Promise<string | null>;
  checkIdle: () => Promise<void>;
  lastActivity: number;
  pendingRenames: { oldPath: string; newPath: string }[];
  drainRenames: () => Promise<void>;
  saved: { locks: Lock[] };
  store: () => Store;
}
async function fixture() {
  (globalThis as unknown as { window: unknown }).window = {
    crypto, setTimeout: () => 1, clearTimeout: () => {}, setInterval: () => 2,
  };
  const [a, b] = await ready;
  const locks: Lock[] = [
    { id: newLockId(crypto), path: '测试文件夹', type: 'folder', ...a.credentials },
    { id: newLockId(crypto), path: '测试文件夹/a.md', type: 'file', ...b.credentials },
  ];
  const plugin = new FolderLockPlugin({} as never, {} as never);
  const harness = plugin as unknown as Harness;
  const files = new Map([['测试文件夹/a.md', { file: new TFile('测试文件夹/a.md'), text: '私人档案' }],
    ['测试文件夹/empty.md', { file: new TFile('测试文件夹/empty.md'), text: '' }],
    ['其他/no.md', { file: new TFile('其他/no.md'), text: 'outside' }]]);
  const folders = new Map([['测试文件夹', new TFolder('测试文件夹')]]);
  const writes: string[] = [];
  let editorScans = 0;
  plugin.app = {
    vault: {
      configDir: '.obsidian',
      getAbstractFileByPath: (path: string) => files.get(path)?.file ?? folders.get(path) ?? null,
      getFiles: () => [...files.values()].map(e => e.file),
      read: async (file: TFile) => files.get(file.path)!.text,
      process: async (file: TFile, transform: (text: string) => string) => {
        const entry = files.get(file.path)!;
        const after = transform(entry.text); entry.text = after; writes.push(file.path); return after;
      },
    },
    workspace: { iterateAllLeaves: () => { editorScans++; } },
  } as never;
  plugin.data = { version: 2, language: 'zh', idleMinutes: 1, locks };
  plugin.state = await inspect(harness.store(), locks);
  harness.keys = new Map([[locks[0].id, a.key], [locks[1].id, b.key]]);
  harness.accessReady = true;
  harness.promptPassword = async lock => lock.id === locks[0].id ? 'outer-pass-1234' : 'inner-pass-5678';
  return { plugin, harness, locks, files, folders, writes, getEditorScans: () => editorScans };
}

test('plugin retains independent unlocked session keys; idle locks all without asking again', async () => {
  const { plugin, harness, locks, files } = await fixture();
  await plugin.run('lock');
  assert.equal(harness.keys.size, 0);
  await plugin.run('unlock', [locks[0].id]);
  assert.equal(harness.keys.size, 1); assert.ok(harness.keys.has(locks[0].id));
  assert.deepEqual(parseEnvelope(files.get('测试文件夹/a.md')!.text)?.layers, [locks[1].id]);
  await plugin.run('unlock', [locks[1].id]);
  assert.equal(harness.keys.size, 2); assert.equal(files.get('测试文件夹/a.md')!.text, '私人档案');
  harness.promptPassword = async () => { throw new Error('idle must not prompt'); };
  harness.lastActivity = Date.now() - 120_000;
  await harness.checkIdle();
  assert.equal(harness.keys.size, 0);
  assert.deepEqual(parseEnvelope(files.get('测试文件夹/a.md')!.text)?.layers, [locks[0].id, locks[1].id]);
  assert.equal(files.get('其他/no.md')!.text, 'outside');
  plugin.onunload();
});
test('wrong password in a later layer leaves files and editor tabs entirely untouched', async () => {
  const { plugin, harness, files, writes, getEditorScans, locks } = await fixture();
  await plugin.run('lock');
  const before = [...files].map(([p, e]) => [p, e.text]), writeCount = writes.length, scans = getEditorScans();
  harness.promptPassword = async lock => lock.id === locks[0].id ? 'outer-pass-1234' : 'WRONG-inner-pass';
  await plugin.run('unlock');
  assert.equal(writes.length, writeCount); assert.equal(getEditorScans(), scans);
  assert.deepEqual([...files].map(([p, e]) => [p, e.text]), before);
  assert.equal(harness.keys.size, 0);
  plugin.onunload();
});
test('password changes only when that specific layer is peeled; data contains no passwords/keys', async () => {
  const { plugin, harness, locks, files } = await fixture();
  await plugin.run('lock');
  await assert.rejects(plugin.savePassword(locks[0], 'outer-pass-1234', 'new-outer-pass'));
  await plugin.run('unlock', [locks[0].id]);
  const innerCipher = files.get('测试文件夹/a.md')!.text;
  await plugin.savePassword(locks[0], 'outer-pass-1234', 'new-outer-pass');
  const updated = plugin.data.locks.find(l => l.id === locks[0].id)!;
  assert.notEqual(updated.salt, locks[0].salt);
  await unlockKey('new-outer-pass', updated, crypto);
  await assert.rejects(unlockKey('outer-pass-1234', updated, crypto));
  assert.equal(files.get('测试文件夹/a.md')!.text, innerCipher);
  const json = JSON.stringify(harness.saved);
  for (const secret of ['outer-pass-1234', 'inner-pass-5678', 'new-outer-pass', 'CryptoKey']) assert.ok(!json.includes(secret));
  assert.deepEqual(Object.keys(harness.saved.locks[0]).sort(), ['id', 'iterations', 'path', 'salt', 'type', 'verifier']);
  plugin.onunload();
});
test('cannot remove or introduce an inner lock while an outer layer is encrypted', async () => {
  const { plugin, locks, files } = await fixture();
  await plugin.run('lock');
  const before = files.get('测试文件夹/a.md')!.text;
  await plugin.removeProtection(locks[1].id);
  assert.equal(plugin.data.locks.length, 2);
  await assert.rejects(plugin.savePassword({ path: '测试文件夹/empty.md', type: 'file' }, '', 'new-inner-pass'));
  assert.equal(plugin.data.locks.length, 2); assert.equal(files.get('测试文件夹/a.md')!.text, before);
  plugin.onunload();
});
test('vault rename queue persists paths and descendants; encrypted content survives rename', async () => {
  const { plugin, harness, locks, files, folders } = await fixture();
  await plugin.run('lock');
  const before = files.get('测试文件夹/a.md')!.text;
  for (const [path, entry] of [...files]) if (path.startsWith('测试文件夹/')) {
    files.delete(path); entry.file.path = path.replace(/^测试文件夹/, '新文件夹'); files.set(entry.file.path, entry);
  }
  folders.delete('测试文件夹'); folders.set('新文件夹', new TFolder('新文件夹'));
  harness.pendingRenames.push({ oldPath: '测试文件夹', newPath: '新文件夹' });
  await harness.drainRenames();
  assert.equal(plugin.data.locks[0].path, '新文件夹'); assert.equal(plugin.data.locks[1].path, '新文件夹/a.md');
  assert.equal(plugin.data.locks[1].id, locks[1].id); assert.equal(harness.saved.locks[0].path, '新文件夹');
  assert.equal(files.get('新文件夹/a.md')!.text, before);
  await plugin.run('unlock');
  assert.equal(files.get('新文件夹/a.md')!.text, '私人档案');
  plugin.onunload();
});
test('unload drops every in-memory key and does not attempt asynchronous encryption', async () => {
  const { plugin, harness, files, writes } = await fixture();
  const before = [...files].map(([p, e]) => [p, e.text]);
  plugin.onunload();
  assert.equal(harness.keys.size, 0); assert.equal(writes.length, 0);
  assert.deepEqual([...files].map(([p, e]) => [p, e.text]), before);
  assert.ok(Notice.messages.length > 0);
});
test('cancelling a later per-lock password prompt does not partially unlock files', async () => {
  const { plugin, harness, locks, files, writes, getEditorScans } = await fixture();
  await plugin.run('lock');
  const before = [...files].map(([p, e]) => [p, e.text]), writeCount = writes.length, scans = getEditorScans();
  harness.promptPassword = async lock => lock.id === locks[0].id ? 'outer-pass-1234' : null;
  await plugin.run('unlock');
  assert.deepEqual([...files].map(([p, e]) => [p, e.text]), before);
  assert.equal(writes.length, writeCount); assert.equal(getEditorScans(), scans); assert.equal(harness.keys.size, 0);
  plugin.onunload();
});
test('adding a standalone lock persists its own metadata before encryption and leaves others intact', async () => {
  const { plugin, harness, files } = await fixture();
  const id = await plugin.savePassword({ path: '其他/no.md', type: 'file' }, '', 'third-independent-pass');
  assert.equal(harness.saved.locks.length, 3);
  assert.equal(harness.saved.locks[2].id, id);
  assert.equal(files.get('其他/no.md')!.text, 'outside');
  await plugin.run('lock', [id]);
  assert.deepEqual(parseEnvelope(files.get('其他/no.md')!.text)?.layers, [id]);
  assert.equal(files.get('测试文件夹/a.md')!.text, '私人档案');
  assert.equal(harness.keys.has(id), false);
  plugin.onunload();
});
test('preflight read errors produce a path-specific state report without any writes', async () => {
  const { plugin, files, writes } = await fixture();
  const original = plugin.app.vault.read.bind(plugin.app.vault);
  plugin.app.vault.read = async file => {
    if (file.path === '测试文件夹/a.md') throw new Error('read failed');
    return original(file);
  };
  let shown = false;
  plugin.showReport = () => { shown = true; };
  await plugin.run('lock');
  assert.equal(shown, true);
  assert.equal(plugin.lastReport?.failure?.path, '测试文件夹/a.md');
  assert.equal(plugin.lastReport?.phase, 'prepare'); assert.equal(writes.length, 0);
  assert.equal(files.get('测试文件夹/empty.md')!.text, '');
  plugin.onunload();
});
test('opening a nested locked file immediately authenticates outer then inner and returns only readable content', async () => {
  const { plugin, harness, locks, files } = await fixture();
  await plugin.run('lock');
  const prompts: string[] = [];
  harness.promptPassword = async lock => { prompts.push(lock.id); return lock.type === 'folder' ? 'outer-pass-1234' : 'inner-pass-5678'; };
  assert.equal(await plugin.openProtectedFile('测试文件夹/a.md'), true);
  assert.deepEqual(prompts, [locks[0].id, locks[1].id]); assert.equal(files.get('测试文件夹/a.md')!.text, '私人档案');
  assert.equal(plugin.isFileLocked('测试文件夹/a.md'), false);
  plugin.onunload();
});
test('cancel or wrong password on file-open denies navigation; an unpeeled inner layer stays encrypted', async () => {
  for (const cancelInner of [false, true]) {
    const { plugin, harness, files, locks } = await fixture();
    await plugin.run('lock'); const outerCipher = files.get('测试文件夹/a.md')!.text;
    harness.promptPassword = async lock => cancelInner ? lock.type === 'folder' ? 'outer-pass-1234' : null : 'wrong-password';
    assert.equal(await plugin.openProtectedFile('测试文件夹/a.md'), false);
    const remaining = parseEnvelope(files.get('测试文件夹/a.md')!.text)!;
    assert.ok(remaining.layers.includes(locks[1].id));
    if (!cancelInner) assert.equal(files.get('测试文件夹/a.md')!.text, outerCipher);
    plugin.onunload();
  }
});
test('opening a folder unlocks only that folder layer, then permits expansion while inner files remain locked', async () => {
  const { plugin, harness, files, locks } = await fixture();
  await plugin.run('lock'); assert.equal(plugin.isFolderLocked('测试文件夹'), true);
  const prompts: string[] = [];
  harness.promptPassword = async lock => { prompts.push(lock.id); return 'outer-pass-1234'; };
  assert.equal(await plugin.openProtectedFolder('测试文件夹'), true);
  assert.deepEqual(prompts, [locks[0].id]); assert.equal(plugin.isFolderLocked('测试文件夹'), false);
  assert.equal(plugin.isFileLocked('测试文件夹/a.md'), true);
  assert.deepEqual(parseEnvelope(files.get('测试文件夹/a.md')!.text)?.layers, [locks[1].id]);
  plugin.onunload();
});
test('deleted configuration is auto-recovered from v2 headers when opening a locked file', async () => {
  const { plugin, harness, files } = await fixture();
  await plugin.run('lock');
  plugin.data = { version: 2, language: 'zh', idleMinutes: 0, locks: [] }; plugin.state = null;
  harness.keys.clear();
  assert.equal(await plugin.openProtectedFile('测试文件夹/a.md'), true);
  assert.equal(plugin.data.locks.length, 2); assert.equal(harness.saved.locks.length, 2);
  assert.equal(files.get('测试文件夹/a.md')!.text, '私人档案');
  plugin.onunload();
});
test('wrong password cannot remove protection, even if the lock is already unlocked', async () => {
  const { plugin, harness, files, locks } = await fixture();
  const before = files.get('测试文件夹/a.md')!.text;
  harness.promptPassword = async () => 'attacker-password';
  await plugin.removeProtection(locks[1].id);
  assert.equal(plugin.data.locks.length, 2); assert.equal(files.get('测试文件夹/a.md')!.text, before);
  harness.promptPassword = async () => 'inner-pass-5678';
  await plugin.removeProtection(locks[1].id);
  assert.equal(plugin.data.locks.length, 1);
  plugin.onunload();
});
test('configuration verifier replacement is reported and cannot trigger silent re-encryption', async () => {
  const { plugin, harness, files, writes } = await fixture();
  await plugin.run('lock');
  const malicious = await createCredentials('attacker-password', crypto);
  plugin.data.locks[0] = { ...plugin.data.locks[0], verifier: malicious.credentials.verifier };
  const before = [...files].map(([p, e]) => [p, e.text]), count = writes.length;
  plugin.showReport = () => {};
  assert.equal(await plugin.openProtectedFile('测试文件夹/a.md'), false);
  assert.equal(plugin.lastReport?.failure?.code, 'headerMismatch');
  assert.deepEqual([...files].map(([p, e]) => [p, e.text]), before); assert.equal(writes.length, count);
  // Explicit recovery repairs the index from authenticated-on-unlock headers, not from the attacker's verifier.
  assert.equal(await plugin.recoverProtection(), true);
  assert.notEqual(plugin.data.locks[0].verifier, malicious.credentials.verifier);
  harness.keys.clear(); plugin.onunload();
});
test('startup navigation waits for the encryption index instead of losing the requested view', async () => {
  const { plugin, harness, writes } = await fixture(); harness.accessReady = false;
  let settled = false;
  const job = plugin.openProtectedFile('其他/no.md').then(value => { settled = true; return value; });
  await Promise.resolve(); assert.equal(settled, false);
  harness.accessReady = true; harness.readyResolve();
  assert.equal(await job, true); assert.equal(writes.length, 0);
  plugin.onunload();
});
test('header-indexed folders remain collapsed after data deletion and recover on click', async () => {
  const { plugin, harness } = await fixture();
  await plugin.run('lock');
  plugin.data = { version: 2, language: 'zh', idleMinutes: 0, locks: [] }; plugin.state = null; harness.keys.clear();
  assert.equal(plugin.isFolderLocked('测试文件夹'), true);
  assert.equal(await plugin.openProtectedFolder('测试文件夹'), true);
  assert.equal(plugin.data.locks.length, 2); assert.equal(plugin.isFolderLocked('测试文件夹'), false);
  assert.equal(plugin.isFileLocked('测试文件夹/a.md'), true);
  plugin.onunload();
});
