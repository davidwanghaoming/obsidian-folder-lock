import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { parseHTML } from 'linkedom';
import FolderLockPlugin from '../src/main';
import { createCredentials } from '../src/crypto';
import { encryptLayer, newLockId, parseEnvelope, V2_MARKER } from '../src/layers';
import { DisplayGuard } from '../src/display-guard';
import { type Lock } from '../src/lock-engine';
import { MarkdownView, Notice, Plugin, TFile, TFolder, WorkspaceLeaf } from './obsidian-mock';
const crypto = webcrypto as unknown as Crypto;
const credentials = Promise.all([createCredentials('fixture-folder-password', crypto), createCredentials('fixture-file-password', crypto)]);

async function reportedVault(options: { unreadyView?: boolean; explorerThrows?: boolean; immediateLayout?: boolean; scanThrows?: boolean; headersThrow?: boolean; layoutThrows?: boolean } = {}) {
  const { window, document } = parseHTML('<html><head></head><body><div class="nav-folder"><div class="nav-folder-title" data-path="人物档案">人物档案</div><div class="nav-folder-children"><div class="nav-file"><div class="nav-file-title" data-path="人物档案/候烨磊.md">候烨磊.md</div></div></div></div></body></html>');
  class KeyEvent extends window.Event { key = ''; }
  Object.assign(globalThis, { document, Element: window.Element, MutationObserver: window.MutationObserver, KeyboardEvent: KeyEvent,
    window: { crypto, setTimeout: () => 1, clearTimeout: () => {}, setInterval: () => 2, clearInterval: () => {} } });
  const [folder, file] = await credentials;
  const locks: Lock[] = [
    { id: newLockId(crypto), type: 'folder', path: '人物档案', ...folder.credentials },
    { id: newLockId(crypto), type: 'file', path: '人物档案/候烨磊.md', ...file.credentials },
  ];
  // Same reported config schema and paths; ALL passwords/IDs/salts/content below are synthetic.
  const data = { version: 2 as const, language: 'zh' as const, idleMinutes: 0, locks };
  const files = new Map<string, { file: TFile; content: string }>();
  for (let i = 0; i < 8; i++) {
    const path = i === 0 ? '人物档案/候烨磊.md' : `人物档案/测试档案${i + 1}.md`;
    let text = i === 7 ? '' : `合成测试正文 ${i}`;
    if (!i) text = await encryptLayer(text, locks[1].id, file.key, crypto, 'legacy locked');
    text = await encryptLayer(text, locks[0].id, folder.key, crypto, 'legacy locked');
    files.set(path, { file: new TFile(path), content: text });
  }
  const meldPath = '人物档案/陈墨涵.mdenc';
  files.set(meldPath, { file: new TFile(meldPath), content: '{"syntheticMeldCiphertext":true}' });
  const folders = new Map([['人物档案', new TFolder('人物档案')]]);
  const handlers = new Map<string, ((...args: any[]) => any)[]>();
  const layout: (() => any)[] = [];
  const reads: string[] = [], writes: string[] = [];
  const leaf = new WorkspaceLeaf();
  if (options.unreadyView) {
    const view = new MarkdownView(); view.file = files.get('人物档案/候烨磊.md')!.file; view.leaf = leaf;
    view.getViewData = () => { throw new TypeError('editor is not ready'); }; leaf.view = view;
  } else leaf.view = { getViewType: () => 'deferred' }; // Obsidian >= 1.7 deferred workspace leaf
  const explorer = { view: { get fileItems(): any {
    if (options.explorerThrows) throw new TypeError('fileItems is not ready');
    return { 人物档案: { file: { path: '人物档案' }, collapsed: false, setCollapsed(value: boolean) { this.collapsed = value; } } };
  } } };
  const plugin = new FolderLockPlugin({} as never, {} as never);
  const mock = plugin as unknown as Plugin;
  mock.loaded = data;
  plugin.app = {
    vault: {
      configDir: '.obsidian',
      getAbstractFileByPath: (path: string) => files.get(path)?.file ?? folders.get(path) ?? null,
      getFiles: () => { if (options.headersThrow) throw new TypeError('getFiles failed'); return [...files.values()].map(entry => entry.file); },
      getMarkdownFiles: () => { if (options.scanThrows) throw new TypeError('getMarkdownFiles failed'); return [...files.values()].filter(entry => /\.md$/i.test(entry.file.path)).map(entry => entry.file); },
      read: async (file: TFile) => { reads.push(file.path); if (file.path === meldPath) throw new Error('.mdenc must not be read'); return files.get(file.path)!.content; },
      process: async (file: TFile, fn: (content: string) => string) => {
        const entry = files.get(file.path)!; entry.content = fn(entry.content); writes.push(file.path); return entry.content;
      },
      on: (name: string, fn: (...args: any[]) => any) => {
        const list = handlers.get(`vault:${name}`) ?? []; list.push(fn); handlers.set(`vault:${name}`, list); return {};
      },
    },
    workspace: {
      on: (name: string, fn: (...args: any[]) => any) => {
        const list = handlers.get(name) ?? []; list.push(fn); handlers.set(name, list); return {};
      },
      iterateAllLeaves: (fn: (leaf: unknown) => void) => fn(leaf),
      getLeavesOfType: (type: string) => type === 'file-explorer' ? [explorer] : [leaf],
      getActiveFile: () => null, getLeaf: () => leaf,
      onLayoutReady: (fn: () => any) => { if (options.layoutThrows) throw new TypeError('onLayoutReady failed'); layout.push(fn); if (options.immediateLayout) return fn(); },
    },
  } as never;
  const harness = plugin as unknown as { promptPassword: (lock: Lock) => Promise<string | null> };
  harness.promptPassword = async () => null;
  plugin.showReport = () => {};
  return { plugin, mock, data, locks, files, reads, writes, handlers, leaf, meldPath,
    document, layout, async flushLayout() { for (const fn of layout) await fn(); await Promise.resolve(); },
    cleanup() { plugin.onunload(); for (const fn of mock.cleanups.reverse()) fn(); } };
}

test('0.2.1 regression: initializing MarkdownView cannot abort UI registration or plugin load', async () => {
  const f = await reportedVault({ unreadyView: true });
  const errors: unknown[][] = []; const oldError = console.error; console.error = (...args: unknown[]) => { errors.push(args); };
  const noticeCount = Notice.messages.length;
  try {
    await assert.doesNotReject(f.plugin.onload()); await f.flushLayout();
    assert.equal(f.mock.ribbons.length, 1); assert.ok(f.mock.commands.length >= 6); assert.equal(f.mock.tabs.length, 1);
    assert.equal(f.handlers.has('file-menu'), true); assert.equal(f.writes.length, 0);
    assert.deepEqual(f.plugin.data, f.data); assert.equal(f.mock.saved, null);
    assert.ok(Notice.messages.slice(noticeCount).some(text => text.startsWith('Folder Lock 启动出错：') && text.includes('editor is not ready')));
    assert.ok(errors.some(args => String(args[0]).includes('editor is not ready')));
    assert.ok(f.leaf.view.containerEl.classList.contains('folder-lock-view-unready'));
  } finally { f.cleanup(); console.error = oldError; }
});
test('reported schema, eight v1 notes and .mdenc initialize without migration, data loss or non-md reads', async () => {
  const f = await reportedVault();
  try {
    await f.plugin.onload(); await f.flushLayout(); await f.plugin.refresh();
    assert.equal(f.mock.ribbons.length, 1); assert.ok(f.mock.commands.length >= 6); assert.ok(f.handlers.has('file-menu'));
    assert.deepEqual(f.plugin.data, f.data); assert.equal(f.plugin.state?.files.length, 8);
    assert.deepEqual(f.plugin.state?.nonMarkdown, [f.meldPath]); assert.equal(f.reads.includes(f.meldPath), false);
    assert.equal(f.plugin.fatal, null); assert.equal(f.writes.length, 0); assert.equal(f.mock.saved, null);
  } finally { f.cleanup(); }
});

async function withDiagnostics(action: (errors: unknown[][]) => Promise<void>): Promise<void> {
  const errors: unknown[][] = [], old = console.error;
  console.error = (...args: unknown[]) => { errors.push(args); };
  try { await action(errors); } finally { console.error = old; }
}
function assertCore(f: Awaited<ReturnType<typeof reportedVault>>): void {
  assert.equal(f.mock.ribbons.length, 1); assert.ok(f.mock.commands.length >= 5);
  assert.equal(f.mock.tabs.length, 1); assert.ok(f.handlers.has('file-menu'));
}

test('reported v1 vault: wrong password changes nothing; original passwords unlock all eight and only next lock upgrades', async () => {
  const f = await reportedVault();
  try {
    const initial = [...f.files].map(([path, entry]) => [path, entry.content]);
    const originalMeld = f.files.get(f.meldPath)!.content;
    await f.plugin.onload(); await f.flushLayout();
    assert.deepEqual([...f.files].map(([path, entry]) => [path, entry.content]), initial);
    assert.equal(f.writes.length, 0); assert.equal(f.mock.saved, null);
    const itemNames: string[] = [];
    const menu = { addItem(fn: (item: any) => void) { const item: any = {
      setTitle(title: string) { itemNames.push(title); return item; }, setIcon() { return item; }, onClick() { return item; },
    }; fn(item); } };
    for (const handler of f.handlers.get('file-menu') ?? []) handler(menu, f.files.get('人物档案/候烨磊.md')!.file);
    assert.ok(itemNames.includes('解锁')); assert.ok(itemNames.includes('取消保护'));
    const harness = f.plugin as unknown as { promptPassword: (lock: Lock) => Promise<string | null> };
    harness.promptPassword = async () => 'incorrect-fixture-password';
    await f.plugin.run('unlock');
    assert.deepEqual([...f.files].map(([path, entry]) => [path, entry.content]), initial); assert.equal(f.writes.length, 0);
    harness.promptPassword = async lock => lock.type === 'folder' ? 'fixture-folder-password' : 'fixture-file-password';
    await f.plugin.run('unlock');
    assert.equal(f.files.get('人物档案/候烨磊.md')!.content, '合成测试正文 0');
    assert.equal(f.files.get('人物档案/测试档案8.md')!.content, '');
    assert.ok([...f.files].filter(([path]) => /\.md$/.test(path)).every(([, entry]) => parseEnvelope(entry.content) === null));
    assert.deepEqual(f.plugin.data, f.data); assert.equal(f.mock.saved, null);
    await f.plugin.run('lock');
    assert.ok([...f.files].filter(([path]) => /\.md$/.test(path)).every(([, entry]) => entry.content.startsWith(V2_MARKER)));
    assert.equal(parseEnvelope(f.files.get('人物档案/候烨磊.md')!.content)?.headers.length, 2);
    assert.equal(f.files.get(f.meldPath)!.content, originalMeld); assert.equal(f.reads.includes(f.meldPath), false);
    assert.equal(f.writes.includes(f.meldPath), false); assert.deepEqual(f.plugin.data, f.data);
  } finally { f.cleanup(); }
});

test('unavailable explorer internals warn but never prevent menu/ribbon registration or legacy loading', async () => {
  await withDiagnostics(async errors => {
    const f = await reportedVault({ explorerThrows: true, immediateLayout: true });
    try {
      await assert.doesNotReject(f.plugin.onload()); await f.plugin.refresh(); assertCore(f);
      assert.equal(f.plugin.fatal, null); assert.ok(errors.some(args => String(args[0]).includes('fileItems is not ready')));
      assert.equal(f.writes.length, 0); assert.equal(f.mock.saved, null);
    } finally { f.cleanup(); }
  });
});

test('all essential UI exists BEFORE an unexpected DisplayGuard.install exception; fallback stays fail-closed', async () => {
  await withDiagnostics(async errors => {
    const f = await reportedVault(), original = DisplayGuard.prototype.install;
    DisplayGuard.prototype.install = () => { assertCore(f); throw new TypeError('unexpected guard install failure'); };
    try {
      await assert.doesNotReject(f.plugin.onload()); await f.flushLayout(); assertCore(f);
      assert.ok(errors.some(args => String(args[0]).includes('unexpected guard install failure')));
      assert.ok(f.document.documentElement.classList.contains('folder-lock-display-failsafe'));
      assert.deepEqual(f.plugin.data, f.data); assert.equal(f.mock.saved, null); assert.equal(f.writes.length, 0);
    } finally { DisplayGuard.prototype.install = original; f.cleanup(); }
  });
});

test('configuration read failure keeps controls available and never resets/saves the original index', async () => {
  await withDiagnostics(async errors => {
    const f = await reportedVault();
    f.mock.loadData = async () => { assertCore(f); throw new Error('loadData failed'); };
    try {
      await assert.doesNotReject(f.plugin.onload()); await f.flushLayout(); assertCore(f);
      assert.equal(f.plugin.fatal, 'dataError'); assert.equal(f.mock.saved, null); assert.equal(f.writes.length, 0);
      assert.ok(errors.some(args => String(args[0]).includes('loadData failed')));
    } finally { f.cleanup(); }
  });
});

test('failed scan, header enumeration and onLayoutReady registration each produce diagnostics without aborting onload', async () => {
  await withDiagnostics(async errors => {
    const f = await reportedVault({ scanThrows: true, headersThrow: true, layoutThrows: true });
    try {
      await assert.doesNotReject(f.plugin.onload()); assertCore(f);
      for (const name of ['getMarkdownFiles failed', 'getFiles failed', 'onLayoutReady failed']) {
        assert.ok(errors.some(args => String(args[0]).includes(name)), name);
      }
      assert.deepEqual(f.plugin.data, f.data); assert.equal(f.mock.saved, null); assert.equal(f.writes.length, 0);
      const harness = f.plugin as unknown as { accessReady: boolean };
      assert.equal(harness.accessReady, true); // no permanently pending startup navigation promise
    } finally { f.cleanup(); }
  });
});

test('config-vs-v2-header mismatch is an operation warning, NOT a plugin load failure', async () => {
  const f = await reportedVault();
  try {
    const [folder] = await credentials;
    const path = '人物档案/测试档案2.md';
    f.files.get(path)!.content = await encryptLayer('合成测试正文 1', f.locks[0].id, folder.key, crypto, '🔒 已上锁', f.locks[0], path);
    const attacker = await createCredentials('synthetic-attacker-password', crypto);
    f.data.locks[0] = { ...f.data.locks[0], verifier: attacker.credentials.verifier };
    const initial = [...f.files].map(([p, entry]) => [p, entry.content]);
    const notices = Notice.messages.length;
    await assert.doesNotReject(f.plugin.onload()); await f.flushLayout(); await f.plugin.refresh(); assertCore(f);
    assert.equal(f.plugin.fatal, null); assert.ok(f.plugin.state?.errors.some(e => e.code === 'headerMismatch'));
    assert.ok(Notice.messages.slice(notices).some(text => text.includes('配置与文件头不一致')));
    assert.deepEqual([...f.files].map(([p, entry]) => [p, entry.content]), initial);
    assert.equal(f.writes.length, 0); assert.equal(f.mock.saved, null);
  } finally { f.cleanup(); }
});

test('one failed command registration does not prevent later commands, context menus or settings', async () => {
  await withDiagnostics(async errors => {
    const f = await reportedVault(), original = f.mock.addCommand.bind(f.mock);
    f.mock.addCommand = command => { if (command.id === 'lock-all') throw new Error('command registration failed'); return original(command); };
    try {
      await assert.doesNotReject(f.plugin.onload()); await f.flushLayout(); assertCore(f);
      assert.ok(f.mock.commands.some(command => command.id === 'unlock-all'));
      assert.ok(errors.some(args => String(args[0]).includes('command registration failed')));
      assert.equal(f.writes.length, 0);
    } finally { f.cleanup(); }
  });
});

test('asynchronous layout callback faults are caught and logged instead of becoming unhandled rejections', async () => {
  await withDiagnostics(async errors => {
    const f = await reportedVault();
    try {
      await f.plugin.onload();
      const harness = f.plugin as unknown as { display: { sync(): void } };
      harness.display.sync = () => { throw new TypeError('layout sync failed'); };
      await assert.doesNotReject(f.flushLayout()); assertCore(f);
      assert.ok(errors.some(args => String(args[0]).includes('layout sync failed')));
      assert.equal(f.writes.length, 0); assert.equal(f.mock.saved, null);
    } finally { f.cleanup(); }
  });
});

test('registering UI before data load still respects saved English and later language changes', async () => {
  const f = await reportedVault();
  f.mock.loadData = async () => { assertCore(f); return { ...f.data, language: 'en' }; };
  try {
    await f.plugin.onload(); await f.flushLayout();
    assert.equal(f.mock.commands.find(command => command.id === 'lock-all').name, f.plugin.t('lockCommand'));
    assert.equal(f.plugin.data.language, 'en'); assert.equal(f.mock.saved, null);
    await f.plugin.setLanguage('zh');
    assert.equal(f.mock.commands.find(command => command.id === 'lock-all').name, f.plugin.t('lockCommand'));
    assert.equal(f.plugin.data.language, 'zh'); assert.equal(f.writes.length, 0);
  } finally { f.cleanup(); }
});
