import test from 'node:test';
import assert from 'node:assert/strict';
import { parseHTML } from 'linkedom';
import { DisplayGuard, type GuardHost } from '../src/display-guard';
import { collapsedArgument, gatedOpen, patchMethod, safeMarkdown } from '../src/guard-core';
import { MarkdownView, MarkdownPreviewView, MarkdownRenderer, Plugin, TFile, WorkspaceLeaf } from './obsidian-mock';

function fixture(options: { model?: boolean } = {}) {
  const { window, document } = parseHTML('<html><head></head><body><div class="nav-folder"><div class="nav-folder-title" data-path="secure">secure</div><div class="nav-folder-children"><div class="nav-file"><div class="nav-file-title" data-path="secure/a.md">a.md</div></div></div></div></body></html>');
  Object.assign(globalThis, { window, document, Element: window.Element, MutationObserver: window.MutationObserver,
    KeyboardEvent: class extends window.Event { key = ''; } });
  const plugin = new Plugin();
  const folder = document.querySelector('.nav-folder') as unknown as HTMLElement;
  const title = document.querySelector('.nav-folder-title') as unknown as HTMLElement;
  let lockedFolder = true, lockedFile = true, allow = false;
  const navLeaf = new WorkspaceLeaf();
  const view = new MarkdownView(); view.file = new TFile('secure/a.md'); view.leaf = navLeaf;
  navLeaf.view = view; navLeaf.state = { type: 'markdown', state: { file: 'previous.md' } };
  const item = { file: { path: 'secure' }, collapsed: false, setCollapsed(value: boolean) {
    this.collapsed = value; folder.classList.toggle('is-collapsed', value); title.setAttribute('aria-expanded', String(!value));
  } };
  const failed: string[] = [], requests: string[] = [];
  const app = {
    workspace: { on: () => ({}), iterateAllLeaves: (fn: any) => fn(navLeaf), getLeaf: () => navLeaf,
      getLeavesOfType: () => [{ view: options.model === false ? {} : { fileItems: { secure: item } } }] },
    vault: { getAbstractFileByPath: (path: string) => new TFile(path) },
  };
  const host: GuardHost = {
    app: app as never, placeholder: () => '🔒 已上锁',
    lockedFile: path => path === 'secure/a.md' && lockedFile,
    lockedFolder: path => path === 'secure' && lockedFolder,
    openFile: async path => { requests.push(path); if (allow) lockedFile = false; return allow; },
    openFolder: async path => { requests.push(path); if (allow) lockedFolder = false; return allow; },
    blockedView: () => false, failed: kind => { failed.push(kind); },
  };
  const guard = new DisplayGuard(plugin as never, host); guard.install(); guard.ready(); view.rendered.length = 0;
  return { guard, plugin, document, window, view, navLeaf, title, folder, item, requests, failed,
    setLockedFile: (value: boolean) => { lockedFile = value; }, setAllow: (value: boolean) => { allow = value; } };
}
const cipher = '%%folder-lock:v1%%\n{"lockId":"secret-metadata"}\nBASE64-CIPHERTEXT';

test('source renderer never receives ciphertext, and saving a placeholder cannot overwrite the file', async () => {
  const f = fixture();
  try {
    f.view.setViewData(cipher, true);
    assert.deepEqual(f.view.rendered, ['🔒 已上锁']); assert.equal(f.view.getViewData(), cipher);
    await f.view.save(); assert.equal(f.view.saves, 0);
    f.guard.sync(); assert.equal(f.view.rendered.length, 1); // no mutation-observer render loop
    f.setLockedFile(false); f.view.setViewData('readable note', true); await f.view.save();
    assert.equal(f.view.getViewData(), 'readable note'); assert.equal(f.view.saves, 1);
  } finally { f.guard.dispose(); }
});
test('preview, hover renderer, legacy renderer and embed postprocessor display only neutral placeholders', async () => {
  const f = fixture();
  try {
    const preview = new MarkdownPreviewView(); preview.file = new TFile('secure/a.md');
    preview.set(cipher, true); assert.equal(preview.data, '🔒 已上锁');
    preview.set('metadata excerpt without a marker', true); assert.equal(preview.data, '🔒 已上锁');
    const element = f.document.createElement('div') as unknown as HTMLElement;
    await MarkdownRenderer.render({} as never, cipher, element); assert.equal(element.textContent, '🔒 已上锁');
    await MarkdownRenderer.renderMarkdown(cipher, element); assert.equal(element.textContent, '🔒 已上锁');
    element.textContent = 'untrusted excerpt'; f.plugin.postProcessor!(element, { sourcePath: 'secure/a.md' });
    assert.equal(element.textContent, '🔒 已上锁');
  } finally { f.guard.dispose(); }
});
test('wrong/cancelled open leaves the previous leaf state and never calls the original open method', async () => {
  const f = fixture();
  try {
    await f.navLeaf.openFile(new TFile('secure/a.md'));
    assert.deepEqual(f.navLeaf.opens, []); assert.equal(f.navLeaf.state.state.file, 'previous.md');
    await f.navLeaf.setViewState({ type: 'markdown', state: { file: 'secure/a.md' } });
    assert.equal(f.navLeaf.state.state.file, 'previous.md');
    f.setAllow(true); await f.navLeaf.openFile(new TFile('secure/a.md'));
    assert.deepEqual(f.navLeaf.opens, ['secure/a.md']);
  } finally { f.guard.dispose(); }
});
test('locked explorer folders collapse, reject model expansion, intercept clicks and gain icons', async () => {
  const f = fixture();
  try {
    assert.equal(f.item.collapsed, true); assert.ok(f.folder.classList.contains('folder-lock-explorer-locked'));
    assert.ok(f.title.querySelector('.folder-lock-badge'));
    f.item.setCollapsed(false); assert.equal(f.item.collapsed, true);
    f.title.dispatchEvent(new f.window.Event('click', { bubbles: true, cancelable: true }));
    await Promise.resolve(); await Promise.resolve();
    assert.deepEqual(f.requests, ['secure']); assert.equal(f.item.collapsed, true);
    f.setAllow(true); f.title.dispatchEvent(new f.window.Event('click', { bubbles: true, cancelable: true }));
    await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
    assert.equal(f.item.collapsed, false); assert.equal(f.folder.classList.contains('folder-lock-explorer-locked'), false);
  } finally { f.guard.dispose(); }
});
test('missing explorer internals degrade to DOM protection plus core modal-on-open, not ciphertext rendering', async () => {
  const f = fixture({ model: false });
  try {
    assert.ok(f.failed.includes('explorer')); assert.equal(f.failed.includes('display'), false);
    assert.ok(f.folder.classList.contains('folder-lock-explorer-locked'));
    f.view.setViewData(cipher, true); assert.equal(f.view.rendered[0], '🔒 已上锁');
    await f.navLeaf.openFile(new TFile('secure/a.md')); assert.deepEqual(f.navLeaf.opens, []);
  } finally { f.guard.dispose(); }
});
test('unload restores ciphertext in memory before removing save guards; never saves a placeholder', () => {
  const f = fixture(); f.view.setViewData(cipher, true);
  f.guard.dispose();
  assert.equal(f.view.getViewData(), cipher); assert.equal(f.view.data, cipher); assert.equal(f.view.saves, 0);
});
test('failed essential core patch keeps global fail-closed display CSS installed', () => {
  const old = WorkspaceLeaf.prototype.openFile;
  (WorkspaceLeaf.prototype as any).openFile = undefined;
  const f = fixture();
  try {
    assert.ok(f.failed.includes('display'));
    assert.ok(f.document.documentElement.classList.contains('folder-lock-display-failsafe'));
    assert.ok(f.document.head.textContent?.includes('visibility:hidden'));
  } finally { f.guard.dispose(); WorkspaceLeaf.prototype.openFile = old; }
});
test('pure gates are fail-closed, sanitization is synchronous, and patch restoration does not clobber later plugins', async () => {
  assert.equal(safeMarkdown(cipher, 'locked'), 'locked'); assert.equal(safeMarkdown('normal', 'locked'), 'normal');
  assert.equal(collapsedArgument(false, true), true);
  let opened = 0;
  await gatedOpen(async () => { throw new Error('cancel'); }, async () => { opened++; }); assert.equal(opened, 0);
  const object = { value: () => 'old' };
  const restore = patchMethod(object, 'value', old => function() { return `${old()}-patched`; });
  assert.equal(object.value(), 'old-patched');
  object.value = () => 'other-plugin'; restore(); assert.equal(object.value(), 'other-plugin');
});
test('stale plaintext cached for a locked source is shielded and never restored or saved on unload', async () => {
  const f = fixture();
  try {
    f.view.setViewData('stale private plaintext', true);
    assert.deepEqual(f.view.rendered, ['🔒 已上锁']);
    await f.view.save(); assert.equal(f.view.saves, 0);
  } finally { f.guard.dispose(); }
  assert.equal(f.navLeaf.detached, true); assert.equal(f.view.rendered.includes('stale private plaintext'), false);
  await f.view.save(); assert.equal(f.view.saves, 0);
});
